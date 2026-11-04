"""CNS Secure Communication Lab - application factory.
Run:  python3 app.py     (or: flask --app app run --host 0.0.0.0 --port 5000)"""
from pathlib import Path

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from datetime import datetime, timezone
import hashlib
from flask_wtf.csrf import CSRFError
from werkzeug.exceptions import HTTPException, InternalServerError

from config import Config
from extensions import csrf, db, login_manager
from services.keys import KeyManager
from services.security_log import log_event


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config.update(overrides or {})
    if app.config.get("TRUST_PROXY"):
        # Trust one local reverse proxy (for example Caddy) for the original
        # scheme, host, port, and client address. Keep Gunicorn on loopback.
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("SECRET_KEY is not set. Run: python3 scripts/init_db.py (creates .env) or set it in the environment.")
    inst = Path(app.config["INSTANCE_DIR"])
    inst.mkdir(parents=True, exist_ok=True)
    explicit_test_database = (overrides or {}).get("SQLALCHEMY_DATABASE_URI")
    if (not app.config.get("SQLALCHEMY_DATABASE_URI")
            or (app.config.get("TESTING") and not explicit_test_database)):
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + (inst / "cns_lab.db").as_posix()
    app.config.setdefault("KEY_DIR", str(inst / "keys"))
    app.extensions["cns_keys"] = KeyManager(app.config["KEY_DIR"], auto_init=app.config["AUTO_INIT_KEYS"])

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"

    import models  # noqa: F401  (register tables)
    with app.app_context():
        from sqlalchemy import inspect, text
        existing_tables = set(inspect(db.engine).get_table_names())
        needs_upgrade_backup = bool(existing_tables and "security_notifications" not in existing_tables)
        if "messages" in existing_tables:
            message_columns = {c["name"] for c in inspect(db.engine).get_columns("messages")}
            needs_upgrade_backup = needs_upgrade_backup or not {"protection", "relay_ip", "relay_report"}.issubset(message_columns)
        if "intercepted_messages" in existing_tables:
            relay_columns = {c["name"] for c in inspect(db.engine).get_columns("intercepted_messages")}
            needs_upgrade_backup = needs_upgrade_backup or not {"envelope_json", "recipient_protected"}.issubset(relay_columns)
        if "security_findings" in existing_tables:
            finding_columns = {c["name"] for c in inspect(db.engine).get_columns("security_findings")}
            needs_upgrade_backup = needs_upgrade_backup or not {"remediation_steps_json", "verification_steps_json"}.issubset(finding_columns)
        database_dialect = db.engine.dialect.name
        if needs_upgrade_backup and database_dialect == "sqlite":
            # Snapshot the current instance once before additive table/column upgrades.
            from scripts.backup_instance import backup
            backup(inst)
        db.create_all()  # creates new lab telemetry/settings tables; existing tables are unchanged
        # Apply the small additive upgrades supported by the existing schema.
        # SQLite uses BLOB/0 defaults; PostgreSQL uses BYTEA/false.
        is_postgres = database_dialect == "postgresql"
        bool_default = "FALSE" if is_postgres else "0"
        binary_type = "BYTEA" if is_postgres else "BLOB"
        migrations = []
        table_names = inspect(db.engine).get_table_names()
        if "messages" in table_names:
            columns = {col["name"] for col in inspect(db.engine).get_columns("messages")}
            if "protection" not in columns:
                migrations.append("ALTER TABLE messages ADD COLUMN protection VARCHAR(24) NOT NULL DEFAULT 'protected'")
            if "relay_ip" not in columns:
                migrations.append("ALTER TABLE messages ADD COLUMN relay_ip VARCHAR(45)")
            if "relay_report" not in columns:
                migrations.append(f"ALTER TABLE messages ADD COLUMN relay_report BOOLEAN NOT NULL DEFAULT {bool_default}")
        if "intercepted_messages" in table_names:
            columns = {col["name"] for col in inspect(db.engine).get_columns("intercepted_messages")}
            if "envelope_json" not in columns:
                migrations.append(f"ALTER TABLE intercepted_messages ADD COLUMN envelope_json {binary_type}")
            if "recipient_protected" not in columns:
                migrations.append(f"ALTER TABLE intercepted_messages ADD COLUMN recipient_protected BOOLEAN NOT NULL DEFAULT {bool_default}")
        if "security_findings" in table_names:
            columns = {col["name"] for col in inspect(db.engine).get_columns("security_findings")}
            if "remediation_steps_json" not in columns:
                migrations.append("ALTER TABLE security_findings ADD COLUMN remediation_steps_json TEXT NOT NULL DEFAULT '[]'")
            if "verification_steps_json" not in columns:
                migrations.append("ALTER TABLE security_findings ADD COLUMN verification_steps_json TEXT NOT NULL DEFAULT '[]'")
        if migrations:
            # Existing state was backed up above before additive in-place upgrades.
            with db.engine.begin() as conn:
                for statement in migrations:
                    conn.execute(text(statement))
        # In-process scanner jobs are intentionally lightweight; mark jobs left
        # by a previous process as incomplete rather than leaving a spinner forever.
        from models import SecurityScan
        stale_scans = SecurityScan.query.filter(SecurityScan.status.in_(("queued", "running"))).all()
        for scan in stale_scans:
            scan.status = "failed"
            scan.progress = 0
            scan.error = "The application restarted before this scan completed. Retry the scan."
            scan.completed_at = datetime.now(timezone.utc).replace(tzinfo=None)
        if stale_scans:
            db.session.commit()
        cert, key = app.config.get("TLS_CERT_FILE"), app.config.get("TLS_KEY_FILE")
        tls_ready = bool(cert and key and Path(cert).is_file() and Path(key).is_file())
        if app.config.get("REQUIRE_HTTPS") and not tls_ready:
            raise RuntimeError("REQUIRE_HTTPS is enabled but TLS_CERT_FILE/TLS_KEY_FILE are missing or unreadable")
        # app.py serves TLS whenever both files are configured. Make the
        # session cookie secure for that listener too, even if REQUIRE_HTTPS
        # is not used as the redirect/HTTP-rejection policy switch.
        if tls_ready:
            app.config["SESSION_COOKIE_SECURE"] = True

    @login_manager.user_loader
    def load_user(uid):
        try:
            user = db.session.get(models.User, int(uid))
        except (TypeError, ValueError):
            return None
        sid = session.get("sid")
        if user and session.get("epoch") == user.session_epoch and sid:
            row = db.session.query(models.UserSession).filter_by(
                sid_hash=hashlib.sha256(sid.encode("utf-8")).hexdigest(),
                user_id=user.id, revoked_at=None).first()
            return user if row else None
        return None

    @app.before_request
    def touch_active_session():
        if app.config.get("REQUIRE_HTTPS") and not request.is_secure:
            from werkzeug.exceptions import abort
            abort(400, description="HTTPS is required. Open this service using its configured https:// address.")
        from flask_login import current_user
        if not current_user.is_authenticated:
            return
        sid = session.get("sid")
        if not sid:
            return
        row = db.session.query(models.UserSession).filter_by(
            sid_hash=hashlib.sha256(sid.encode("utf-8")).hexdigest(),
            user_id=current_user.id, revoked_at=None).first()
        if row is None:
            return
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if (now - row.last_seen_at).total_seconds() >= 60:
            row.last_seen_at = now
            db.session.commit()

    @login_manager.unauthorized_handler
    def unauthorized():
        log_event("access_denied", "warning", detail=f"unauthenticated {request.method} {request.path}")
        if request.path.startswith(("/api/", "/lab/run/")):
            return jsonify(error="authentication required"), 401
        return redirect(url_for("auth.login", next=request.path))

    from routes.auth import bp as auth_bp
    from routes.messaging import bp as msg_bp
    from routes.dashboard import bp as dash_bp
    from routes.api import bp as api_bp
    from routes.lab import bp as lab_bp
    from routes.settings import bp as settings_bp
    from routes.attacker import bp as attacker_bp
    from routes.virus_scanner import bp as virus_bp
    from routes.security_center import bp as security_center_bp
    from routes.files import bp as files_bp
    from routes.account import bp as account_bp
    for bp in (auth_bp, msg_bp, dash_bp, api_bp, lab_bp, settings_bp, attacker_bp, virus_bp, security_center_bp, files_bp, account_bp):
        app.register_blueprint(bp)

    @app.context_processor
    def notification_badge():
        def asset_version(filename):
            static_root = Path(app.static_folder).resolve()
            asset = (static_root / filename).resolve()
            if not asset.is_relative_to(static_root) or not asset.is_file():
                return "missing"
            # Content-derived URLs invalidate old browser caches even when a
            # deploy preserves file timestamps.
            return hashlib.sha256(asset.read_bytes()).hexdigest()[:12]

        from flask_login import current_user
        if not current_user.is_authenticated:
            return {"unread_notifications": 0, "asset_version": asset_version}
        from models import SecurityNotification
        return {"unread_notifications": SecurityNotification.query.filter_by(user_id=current_user.id, read_at=None).count(),
                "asset_version": asset_version}

    def _is_api():
        return request.path.startswith("/api/") or request.path.startswith("/lab/run/")

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        try:
            log_event("csrf_failure", "warning", detail=f"{request.method} {request.path}: {e.description}")
        except Exception:
            db.session.rollback()
        if _is_api():
            return jsonify(error="CSRF validation failed", detail=e.description), 400
        return render_template("error.html", code=400,
                               message="Your form security token expired or did not match this session. Reload the form and submit again.",
                               retry_url=request.path), 400

    @app.errorhandler(HTTPException)
    def http_error(e):
        if _is_api():
            return jsonify(error=e.name, status=e.code), e.code
        message = e.description if e.code == 400 and e.description else e.name
        return render_template("error.html", code=e.code, message=message), e.code

    @app.errorhandler(Exception)
    def unhandled(e):
        db.session.rollback()
        app.logger.exception("unhandled error")
        try:
            log_event("server_error", "critical", detail=f"{type(e).__name__} on {request.method} {request.path}")
        except Exception:
            db.session.rollback()
        return http_error(InternalServerError())

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; "
            "base-uri 'self'; form-action 'self'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        # Flask-WTF's HTTPS CSRF check requires a Referer on same-origin unsafe requests.
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.is_secure:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000"
        if not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    from services.crypto import b64e
    app.jinja_env.filters["b64"] = b64e

    @app.get("/")
    def index():
        from flask_login import current_user
        return redirect(url_for("dashboard.dashboard" if current_user.is_authenticated else "auth.login"))

    return app


if __name__ == "__main__":
    application = create_app()
    tls = None
    if application.config.get("TLS_CERT_FILE") and application.config.get("TLS_KEY_FILE"):
        tls = (application.config["TLS_CERT_FILE"], application.config["TLS_KEY_FILE"])
    if application.config.get("REQUIRE_HTTPS") and tls is None:
        raise RuntimeError("HTTPS is required but no TLS certificate and key are configured")
    application.run(host=application.config["APP_HOST"], port=application.config["APP_PORT"], debug=False, ssl_context=tls)
