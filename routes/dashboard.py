import csv
import io
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, make_response, redirect, render_template, request
from flask_login import current_user, login_required
from sqlalchemy import and_, func, or_

from models import InterceptedMessage, LoginAttempt, MalwareScan, Message, SecurityEvent, SecurityNotification, User, UserSession
from extensions import db
from models.base import utcnow
from services import messaging
from services.health import health, system_status
from services.scanner import scanner_status
from services.roles import client_user_condition, client_users

bp = Blueprint("dashboard", __name__)


def my_events_query():
    q = SecurityEvent.query
    if not current_user.is_admin:
        q = q.filter(or_(SecurityEvent.user_id == current_user.id, SecurityEvent.username == current_user.username))
    return q


def apply_event_filters(query, args):
    date_from = (args.get("date_from") or "")[:10]
    date_to = (args.get("date_to") or "")[:10]
    if bool(date_from) != bool(date_to):
        return None
    if date_from:
        try:
            first, last = date.fromisoformat(date_from), date.fromisoformat(date_to)
            if last < first or (last - first).days > 365:
                return None
        except ValueError:
            return None
        query = query.filter(SecurityEvent.created_at >= datetime.combine(first, datetime.min.time()),
                             SecurityEvent.created_at <= datetime.combine(last, datetime.max.time()))
    severity = (args.get("severity") or "")[:10]
    category = (args.get("category") or "")[:40]
    term = (args.get("q") or "")[:100].strip()
    if severity in ("info", "warning", "critical"):
        query = query.filter(SecurityEvent.severity == severity)
    if category:
        query = query.filter(SecurityEvent.event_type == category)
    if term:
        pattern = f"%{term}%"
        query = query.filter(or_(SecurityEvent.event_type.ilike(pattern),
                                 SecurityEvent.username.ilike(pattern), SecurityEvent.detail.ilike(pattern)))
    return query


def dashboard_data(user, period_days=30):
    visible_messages = _scoped_message_query(user).all()
    statuses = [messaging.verify_signature_status(m) for m in visible_messages]
    recent = _scoped_message_query(user).filter(
        or_(Message.sender_id == user.id, Message.recipient_id == user.id)
    ).order_by(Message.id.desc()).limit(5).all()
    relay_query = InterceptedMessage.query
    if not user.is_admin:
        client_usernames = client_users(db.session.query(User.username))
        relay_query = relay_query.filter(or_(
            and_(InterceptedMessage.sender_username == user.username,
                 InterceptedMessage.recipient_username.in_(client_usernames)),
            and_(InterceptedMessage.recipient_username == user.username,
                 InterceptedMessage.sender_username.in_(client_usernames))))
    relay_counts = {status: relay_query.filter_by(status=status).count()
                    for status in ("pending", "forwarded", "tampered", "dropped")}
    scan_query = MalwareScan.query if user.is_admin else MalwareScan.query.filter_by(user_id=user.id)
    scan_counts = {status: scan_query.filter_by(status=status).count()
                   for status in ("clean", "infected", "suspicious", "failed")}
    period_events = my_events_query().filter(SecurityEvent.created_at >= utcnow() - timedelta(days=period_days))
    attempts = LoginAttempt.query if user.is_admin else LoginAttempt.query.filter_by(username=user.username)
    active_sessions = UserSession.query.filter(UserSession.revoked_at.is_(None),
                                                UserSession.last_seen_at >= utcnow() - timedelta(minutes=30))
    if not user.is_admin:
        active_sessions = active_sessions.filter_by(user_id=user.id)
    return {
        "users": client_users().count(),
        "total_messages": len(visible_messages),
        "delivered": len(visible_messages),  # message rows exist only after delivery
        "inbox": _scoped_message_query(user).filter_by(recipient_id=user.id).count(),
        "sent": _scoped_message_query(user).filter_by(sender_id=user.id).count(),
        "verified": statuses.count("verified"),
        "unprotected": statuses.count("unprotected"),
        "failed": sum(s not in ("verified", "unprotected") for s in statuses),
        "recent": [messaging.summary(m, user) for m in recent],
        "events": period_events.order_by(SecurityEvent.id.desc()).limit(8).all(),
        "event_total": period_events.count(),
        "critical": period_events.filter(SecurityEvent.severity == "critical").count(),
        "period_days": period_days,
        "relay": relay_counts,
        "scans": scan_counts,
        "login_success": attempts.filter_by(success=True).count(),
        "login_failed": attempts.filter_by(success=False).count(),
        "active_sessions": active_sessions.count(),
        "file_events": my_events_query().filter(SecurityEvent.event_type.like("file_%")).count(),
        "recent_scans": scan_query.order_by(MalwareScan.id.desc()).limit(5).all(),
    }


@bp.get("/dashboard")
@login_required
def dashboard():
    period_days = request.args.get("days", 30, type=int)
    if period_days not in (7, 30, 90):
        period_days = 30
    return render_template("dashboard.html", d=dashboard_data(current_user, period_days), health=health(),
                           diagnostics=diagnostic_components())


def _scoped_message_query(user):
    query = Message.query
    if not user.is_admin:
        query = query.filter(or_(
            and_(Message.sender_id == user.id, Message.recipient.has(client_user_condition())),
            and_(Message.recipient_id == user.id, Message.sender.has(client_user_condition()))))
    return query


def _bucket_key(dt, hourly):
    return dt.strftime("%Y-%m-%d %H:00" if hourly else "%Y-%m-%d")


def _series(rows, start, end, hourly=False):
    step = timedelta(hours=1) if hourly else timedelta(days=1)
    labels, cursor = [], start
    while cursor <= end:
        labels.append(_bucket_key(cursor, hourly))
        cursor += step
    counts = {label: 0 for label in labels}
    for value in rows:
        key = _bucket_key(value, hourly)
        if key in counts:
            counts[key] += 1
    return [{"label": key, "count": counts[key]} for key in labels]


def dashboard_metrics(user, args):
    """Bounded, database-derived chart series; never includes message bodies or addresses."""
    now = datetime.now(timezone.utc).replace(tzinfo=None, minute=0, second=0, microsecond=0)
    days = args.get("days", "30")
    hourly = days == "24h"
    if hourly:
        start, end = now - timedelta(hours=23), now
    elif days == "custom":
        try:
            dfrom = date.fromisoformat(args.get("date_from", ""))
            dto = date.fromisoformat(args.get("date_to", ""))
            if dto < dfrom or (dto - dfrom).days > 365:
                raise ValueError
            start, end = datetime.combine(dfrom, datetime.min.time()), datetime.combine(dto, datetime.max.time())
        except ValueError:
            return None
    else:
        try:
            n = int(days)
        except (ValueError, TypeError):
            n = 30
        if n not in (7, 30, 90):
            n = 30
        today = datetime.now(timezone.utc).replace(tzinfo=None, hour=0, minute=0, second=0, microsecond=0)
        start, end = today - timedelta(days=n - 1), today + timedelta(days=1) - timedelta(microseconds=1)

    event_q = my_events_query().filter(SecurityEvent.created_at >= start, SecurityEvent.created_at <= end)
    event_type = (args.get("event_type") or "")[:40]
    severity = (args.get("severity") or "")[:10]
    if event_type:
        event_q = event_q.filter(SecurityEvent.event_type == event_type)
    if severity in ("info", "warning", "critical"):
        event_q = event_q.filter(SecurityEvent.severity == severity)
    event_times = [x[0] for x in event_q.with_entities(SecurityEvent.created_at).all()]
    timeline = _series(event_times, start, end, hourly)
    message_rows = _scoped_message_query(user).all()
    integrity = {k: 0 for k in ("verified", "invalid", "errors", "unprotected")}
    for message in message_rows:
        state = messaging.verify_signature_status(message)
        if state == "verified": integrity["verified"] += 1
        elif state == "signature_invalid": integrity["invalid"] += 1
        elif state == "unprotected": integrity["unprotected"] += 1
        else: integrity["errors"] += 1

    relay_q = InterceptedMessage.query
    if not user.is_admin:
        client_usernames = client_users(db.session.query(User.username))
        relay_q = relay_q.filter(or_(
            and_(InterceptedMessage.sender_username == user.username,
                 InterceptedMessage.recipient_username.in_(client_usernames)),
            and_(InterceptedMessage.recipient_username == user.username,
                 InterceptedMessage.sender_username.in_(client_usernames))))
    relay_q = relay_q.filter(InterceptedMessage.created_at >= start, InterceptedMessage.created_at <= end)
    attacker = {"intercepted": relay_q.count(), "unchanged_forwarded": relay_q.filter_by(status="forwarded").count(),
                "modified_forwarded": relay_q.filter_by(status="tampered").count(),
                "dropped": relay_q.filter_by(status="dropped").count()}
    login_q = LoginAttempt.query.filter(LoginAttempt.created_at >= start, LoginAttempt.created_at <= end)
    if not user.is_admin:
        login_q = login_q.filter(LoginAttempt.username == user.username)
    login_rows = login_q.all()
    login_success = [r.created_at for r in login_rows if r.success]
    login_failed = [r.created_at for r in login_rows if not r.success]
    if event_type == "login_success": login_failed = []
    elif event_type == "login_failed": login_success = []
    elif event_type and event_type not in ("login_success", "login_failed"): login_success, login_failed = [], []
    logins = {"successful": _series(login_success, start, end, hourly),
              "failed": _series(login_failed, start, end, hourly)}
    scan_q = MalwareScan.query.filter(MalwareScan.created_at >= start, MalwareScan.created_at <= end)
    if not user.is_admin:
        scan_q = scan_q.filter(MalwareScan.user_id == user.id)
    scans = {status: scan_q.filter_by(status=status).count() for status in ("clean", "infected", "suspicious", "failed")}
    severity_rows = event_q.with_entities(SecurityEvent.severity, func.count(SecurityEvent.id)).group_by(SecurityEvent.severity).all()
    severity_counts = {name: 0 for name in ("info", "warning", "critical")}
    severity_counts.update({name: count for name, count in severity_rows if name in severity_counts})
    all_events = event_q.all()
    groups = {"authentication": 0, "message and relay": 0, "malware scanning": 0,
              "file integrity and sharing": 0, "other security": 0}
    for row in all_events:
        name = row.event_type
        if name.startswith(("login", "logout", "session", "register", "password")): key = "authentication"
        elif "message" in name or "relay" in name: key = "message and relay"
        elif name.startswith("malware_scan_"): key = "malware scanning"
        elif name.startswith(("file_", "share_")): key = "file integrity and sharing"
        else: key = "other security"
        groups[key] += 1
    integrity_events = my_events_query().filter(SecurityEvent.created_at >= start, SecurityEvent.created_at <= end,
                                                   SecurityEvent.event_type.in_(("file_integrity_verified", "file_integrity_failure")))
    file_integrity = {"successful": integrity_events.filter_by(event_type="file_integrity_verified").count(),
                      "failed": integrity_events.filter_by(event_type="file_integrity_failure").count()}
    categories = [r[0] for r in my_events_query().with_entities(SecurityEvent.event_type).distinct().order_by(SecurityEvent.event_type).all()]
    return {"range": {"from": start.isoformat(), "to": end.isoformat(), "bucket": "hour" if hourly else "day"},
            "timeline": timeline, "integrity": integrity, "attacker": attacker, "logins": logins,
            "scans": scans, "severity": severity_counts, "file_integrity": file_integrity,
            "activity": groups, "event_types": categories,
            "definitions": {"integrity": "Each visible message counted once by current server-side signature verification; plaintext relay is separate.",
                            "attacker": "InterceptedMessage records in range; status separates original, edited, dropped and pending.",
                            "severity": "Only stored event severities are counted: info, warning and critical."}}


@bp.get("/api/dashboard/metrics")
@login_required
def dashboard_metrics_api():
    data = dashboard_metrics(current_user, request.args)
    return (jsonify(error="Invalid date range; use a maximum 365-day custom range."), 400) if data is None else jsonify(data)


def diagnostic_components():
    """Safe health statuses for actual runtime checks; no paths, keys, or secrets."""
    checks = []
    checks.append({"name": "Flask application", "status": "HEALTHY", "detail": "Request handled by the active application."})
    try:
        from sqlalchemy import inspect, text
        from extensions import db
        db.session.execute(text("SELECT 1"))
        tables = set(inspect(db.engine).get_table_names())
        required = {"users", "messages", "security_events", "security_notifications", "malware_scans", "intercepted_messages", "security_scans", "security_findings"}
        missing = sorted(required - tables)
        checks.append({"name": "Database and schema", "status": "HEALTHY" if not missing else "DEGRADED",
                       "detail": "Connection and required tables verified." if not missing else "Required schema tables are missing."})
    except Exception:
        db.session.rollback()
        checks.append({"name": "Database and schema", "status": "UNAVAILABLE", "detail": "Database query failed."})
    from services.health import key_manager_check
    key_status = key_manager_check()
    if key_status["state"] == "HEALTHY":
        key_detail = (f"Active master key loaded; AES-GCM self-check and {key_status['user_keys_checked']} database signing-key pair(s) verified. "
                      "Stored messages were not decrypted by this check.")
    elif not key_status["permissions_checked"]:
        key_detail = (f"Key loading and {key_status['user_keys_checked']} database signing-key pair(s) were checked, "
                      "but Windows ACL permissions were not reviewed. Stored messages were not decrypted.")
    else:
        failures = []
        if not key_status["master_present"]:
            failures.append("master key is missing")
        if key_status["permissions_ok"] is False:
            failures.append("key file permissions are too broad or key files cannot be inspected")
        if not key_status["key_pairings_ok"]:
            failures.append(
                f"signing-key check failed ({key_status['user_keys_checked']} of "
                f"{key_status['user_key_count']} stored account key(s) checked)"
            )
        key_detail = ("; ".join(failures) or "key checks failed") + ". Stored messages were not decrypted."
    checks.append({"name": "Cryptographic keys", "status": key_status["state"], "detail": key_detail})
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        probe_key = Ed25519PrivateKey.generate()
        probe = b"cns-signature-health-check"
        probe_key.public_key().verify(probe_key.sign(probe), probe)
        crypto_ok = True
    except Exception:
        crypto_ok = False
    checks.append({"name": "Signature verification", "status": "HEALTHY" if crypto_ok else "UNAVAILABLE",
                   "detail": "Ed25519 signing and verification self-check passed." if crypto_ok else "Cryptographic signing self-check failed."})
    https_required = bool(current_app.config.get("REQUIRE_HTTPS"))
    tls_files = all(current_app.config.get(k) and __import__("pathlib").Path(current_app.config[k]).is_file() for k in ("TLS_CERT_FILE", "TLS_KEY_FILE"))
    if tls_files:
        try:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(current_app.config["TLS_CERT_FILE"], current_app.config["TLS_KEY_FILE"])
        except (OSError, ssl.SSLError):
            tls_files = False
    proxy_https = bool(current_app.config.get("TRUST_PROXY") and request.is_secure)
    tls_status = "HEALTHY" if tls_files or proxy_https else ("UNAVAILABLE" if https_required else "NOT CONFIGURED")
    tls_detail = (
        f"A valid TLS certificate is configured; this request used {request.scheme.upper()} at {request.host}."
        if tls_files else
        f"HTTPS is terminated by the configured trusted proxy; the forwarded request used {request.scheme.upper()} at {request.host}."
        if proxy_https else
        "HTTPS is required but certificate files are unavailable." if https_required else
        f"No TLS listener or trusted HTTPS proxy is configured; this request used {request.scheme.upper()} at {request.host}."
    )
    checks.append({"name": "HTTPS and certificates", "status": tls_status, "detail": tls_detail})
    secure_cookie = bool(current_app.config.get("SESSION_COOKIE_SECURE"))
    cookie_mismatch = secure_cookie and not request.is_secure
    checks.append({"name": "Session cookie and current protocol",
                   "status": "DEGRADED" if cookie_mismatch else "HEALTHY" if request.is_secure else "NOT CONFIGURED",
                   "detail": ("This request used HTTP while the session cookie requires HTTPS; sign in and use the HTTPS origin consistently." if cookie_mismatch
                              else f"Current request scheme is {request.scheme.upper()} at {request.host}; session cookies are {'Secure' if secure_cookie else 'not marked Secure'}.")})
    checks.append({"name": "CSRF protection", "status": "HEALTHY" if "csrf" in current_app.extensions else "UNAVAILABLE",
                   "detail": "Flask-WTF CSRF extension is initialized." if "csrf" in current_app.extensions else "CSRF extension is not initialized."})
    import os
    import tempfile
    binary = current_app.config["CLAMSCAN_PATH"]
    available = scanner_status(binary)["available"]
    checks.append({"name": "ClamAV scanner", "status": "HEALTHY" if available else "UNAVAILABLE",
                   "detail": "clamscan executable is available; signature freshness is checked by ClamAV." if available else "clamscan executable was not found; uploads requiring scans are blocked."})
    vt_configured = bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip())
    checks.append({"name": "VirusTotal multi-engine scanning", "status": "HEALTHY" if vt_configured else "NOT CONFIGURED",
                   "detail": "Provider key is configured; file samples are uploaded only after per-scan consent." if vt_configured else "Optional multi-engine scanning is off; configure VIRUSTOTAL_API_KEY to enable consent-based scans."})
    storage = __import__("pathlib").Path(current_app.config["INSTANCE_DIR"]) / "shared-files"
    writable = False
    try:
        storage.mkdir(parents=True, exist_ok=True)
        fd, probe = tempfile.mkstemp(prefix=".health-check-", dir=storage)
        os.close(fd)
        os.unlink(probe)
        writable = True
    except OSError:
        pass
    checks.append({"name": "Private file storage", "status": "HEALTHY" if writable else "UNAVAILABLE",
                   "detail": "Private storage directory passed a write check." if writable else "Private storage directory is not writable."})
    try:
        from models import SecurityScan
        active_scans = SecurityScan.query.filter(SecurityScan.status.in_(("queued", "running"))).count()
        checks.append({"name": "Security analysis jobs", "status": "HEALTHY",
                       "detail": f"In-process bounded scan executor is available; {active_scans} scan job(s) are queued or running."})
    except Exception:
        db.session.rollback()
        checks.append({"name": "Security analysis jobs", "status": "UNAVAILABLE",
                       "detail": "The scan job table or database is unavailable."})
    return [{**item, "checked_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")} for item in checks]


@bp.get("/api/diagnostics")
@login_required
def diagnostics_api():
    checks = diagnostic_components()
    unhealthy = any(c["status"] in ("UNAVAILABLE", "DEGRADED") for c in checks)
    return jsonify(components=checks, status="DEGRADED" if unhealthy else "HEALTHY")


@bp.get("/notifications")
@login_required
def notifications():
    rows = SecurityNotification.query.filter_by(user_id=current_user.id).order_by(SecurityNotification.id.desc()) \
        .paginate(page=request.args.get("page", 1, type=int), per_page=30, max_per_page=30, error_out=False)
    return render_template("notifications.html", rows=rows)


@bp.post("/notifications/<int:notification_id>/read")
@login_required
def notification_read(notification_id):
    row = SecurityNotification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    if row.read_at is None:
        row.read_at = utcnow()
        db.session.commit()
    return redirect(request.referrer or "/notifications")


@bp.post("/notifications/read-all")
@login_required
def notifications_read_all():
    SecurityNotification.query.filter_by(user_id=current_user.id, read_at=None).update({"read_at": utcnow()}, synchronize_session=False)
    db.session.commit()
    return redirect("/notifications")


@bp.get("/events")
@login_required
def events():
    query = my_events_query()
    severity = request.args.get("severity", "")[:10]
    category = request.args.get("category", "")[:40]
    term = request.args.get("q", "")[:100].strip()
    if severity in ("info", "warning", "critical"):
        query = query.filter(SecurityEvent.severity == severity)
    else:
        severity = ""
    if category:
        query = query.filter(SecurityEvent.event_type == category)
    if term:
        pattern = f"%{term}%"
        query = query.filter(or_(SecurityEvent.event_type.ilike(pattern),
                                 SecurityEvent.username.ilike(pattern), SecurityEvent.detail.ilike(pattern)))
    date_from, date_to = request.args.get("date_from", "")[:10], request.args.get("date_to", "")[:10]
    query = apply_event_filters(query, {"date_from": date_from, "date_to": date_to})
    if query is None:
        return render_template("error.html", code=400, message="Choose a valid date range no longer than 365 days."), 400
    pagination = query.order_by(SecurityEvent.id.desc()).paginate(page=request.args.get("page", 1, type=int),
                                                                  per_page=50, max_per_page=50, error_out=False)
    categories = [r[0] for r in my_events_query().with_entities(SecurityEvent.event_type).distinct().order_by(SecurityEvent.event_type).all()]
    return render_template("events.html", rows=pagination.items, pagination=pagination,
                           severity=severity, category=category, q=term, categories=categories,
                           date_from=date_from, date_to=date_to)


@bp.get("/events.csv")
@login_required
def events_csv():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["timestamp_utc", "category", "severity", "username", "source_ip", "detail",
                     "report_generated_at_utc", "metric_definition"])
    query = apply_event_filters(my_events_query(), request.args)
    if query is None:
        return render_template("error.html", code=400, message="Choose a valid date range no longer than 365 days."), 400
    generated = datetime.now(timezone.utc).isoformat()
    rows = query.order_by(SecurityEvent.id.desc()).limit(2000).all()
    for row in rows:
        values = [row.created_at.isoformat() + "Z", row.event_type, row.severity,
                  row.username or "", row.ip or "", row.detail, generated,
                  "One row per authorized stored security event; maximum 2000 rows."]
        writer.writerow([("'" + str(v) if str(v).lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else v) for v in values])
    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=cns-security-events.csv"
    return response


@bp.get("/status")
@login_required
def status():
    return render_template("status.html", s=system_status())
