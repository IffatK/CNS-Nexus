from urllib.parse import urlparse
import hashlib
import secrets

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from forms import LoginForm, RegisterForm
from models.user import User
from models.security import UserSession
from models.base import utcnow
from services import rate_limit
from services.security_log import log_event

bp = Blueprint("auth", __name__)
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing")


def _safe_next(target):
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return None
    p = urlparse(target)
    return target if not p.netloc and not p.scheme else None


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    form = RegisterForm()
    if request.method == "POST" and not form.validate():
        log_event("register_rejected", "info", detail="validation failed", username=form.username.data)
        return render_template("register.html", form=form), 400
    if form.validate_on_submit():
        username = form.username.data.strip().lower()
        if User.query.filter_by(username=username).first():
            form.username.errors.append("That username is taken.")
            log_event("register_rejected", "info", detail="username taken", username=username)
            return render_template("register.html", form=form), 409
        keys = current_app.extensions["cns_keys"]
        user = User(username=username, password_hash=generate_password_hash(form.password.data),
                    public_key="pending",
                    is_admin=username in current_app.config["ADMIN_USERNAMES"])
        db.session.add(user)
        key_created = False
        try:
            db.session.flush()
            user.public_key = keys.create_user_keypair(user.id)
            key_created = True
            db.session.commit()
        except (IntegrityError, OSError, RuntimeError):
            current_app.logger.exception("Registration failed while creating the account or signing key")
            db.session.rollback()
            # The database and local key file cannot share a transaction. If
            # this request created a new key but the insert failed, remove only
            # that new key so a retry does not collide with an orphaned ID.
            if key_created and user.id:
                try:
                    keys.delete_user_key(user.id)
                except OSError:
                    current_app.logger.exception("Could not remove orphaned signing key after registration rollback")
            log_event("register_failed", "critical", detail="could not create account/keypair", username=username)
            form.username.errors.append("Registration failed; see server log.")
            return render_template("register.html", form=form), 500
        log_event("register", "info", user=user, detail="account created, Ed25519 keypair generated")
        flash("Account created. Please log in.", "ok")
        return redirect(url_for("auth.login"))
    return render_template("register.html", form=form)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard"))
    form = LoginForm()
    if request.method == "POST":
        if not form.validate():
            return render_template("login.html", form=form), 400
        username = form.username.data.strip().lower()
        ip = request.remote_addr
        wait = rate_limit.login_lock_remaining(username, ip)
        if wait:
            log_event("login_throttled", "warning", detail=f"locked for ~{wait}s", username=username)
            resp = render_template("login.html", form=form, error=f"Too many failed attempts. Try again in {wait} seconds.")
            return resp, 429, {"Retry-After": str(wait)}
        user = User.query.filter_by(username=username).first()
        ok = check_password_hash(user.password_hash if user else _DUMMY_HASH, form.password.data)
        if user and ok:
            rate_limit.record_login_attempt(username, ip, True)
            session.clear()
            login_user(user, remember=False)
            session["epoch"] = user.session_epoch
            sid = secrets.token_urlsafe(32)
            session["sid"] = sid
            session.permanent = True
            db.session.add(UserSession(sid_hash=hashlib.sha256(sid.encode("utf-8")).hexdigest(),
                                       user_id=user.id, ip=ip or "unknown",
                                       user_agent=(request.user_agent.string or "unknown")[:300]))
            db.session.commit()
            log_event("login_success", "info", user=user, detail="login ok")
            log_event("session_created", "info", user=user, detail="new authenticated browser session")
            nxt = _safe_next(request.args.get("next") or request.form.get("next"))
            return redirect(nxt or url_for("dashboard.dashboard"))
        rate_limit.record_login_attempt(username, ip, False)
        log_event("login_failed", "warning", user=user, username=username,
                  detail="invalid credentials" + ("" if user else " (unknown user)"))
        return render_template("login.html", form=form, error="Invalid username or password."), 401
    return render_template("login.html", form=form)


@bp.post("/logout")
@login_required
def logout():
    user = current_user._get_current_object()
    sid = session.get("sid", "")
    row = UserSession.query.filter_by(sid_hash=hashlib.sha256(sid.encode("utf-8")).hexdigest(),
                                      user_id=user.id, revoked_at=None).first()
    if row:
        row.revoked_at = utcnow()
        db.session.commit()
    log_event("logout", "info", user=user, detail="session invalidated")
    logout_user()
    session.clear()
    flash("Logged out.", "ok")
    return redirect(url_for("auth.login"))
