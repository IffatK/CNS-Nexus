from flask import Blueprint, flash, redirect, render_template, url_for, request
from flask_login import current_user, login_required

from forms import ComposeForm
from services import messaging
from services.messaging import MessagingError
from routes.settings import get_settings
from extensions import db
from models import LabCapture, InterceptedMessage, User
from services.security_log import log_event
from services.roles import client_users

bp = Blueprint("messaging", __name__)


def _compose_page(form, status=200, protection_enabled=None):
    users_query = User.query.filter(User.id != current_user.id)
    if not current_user.is_admin:
        users_query = client_users(users_query)
    users = users_query.order_by(User.username.asc()).all()
    if protection_enabled is None:
        protection_enabled = get_settings(current_user).protection_enabled
    return render_template("compose.html", form=form, users=users,
                           protection_enabled=protection_enabled), status


@bp.route("/compose", methods=["GET", "POST"])
@login_required
def compose():
    form = ComposeForm()
    if form.validate_on_submit():
        recipient = messaging.find_user(form.recipient.data, current_user)
        if recipient is None:
            form.recipient.errors.append("Recipient not found.")
            return _compose_page(form, 404)
        body = form.body.data
        sender_protected = get_settings(current_user).protection_enabled
        recipient_settings = get_settings(recipient)
        allowed, message = messaging.plaintext_relay_policy(sender_protected, recipient_settings.protection_enabled)
        if not allowed:
            message = "Please submit with JavaScript enabled to use sender-side protected transport."
            flash(message, "warning")
            return _compose_page(form, 409, sender_protected)
        try:
            envelope = messaging.prepare_intercepted_envelope(current_user, recipient.username, body)
        except MessagingError as exc:
            flash(exc.message, "warning")
            return _compose_page(form, exc.status, False)
        item = InterceptedMessage(sender_username=current_user.username, recipient_username=recipient.username,
                                  original_body=body, source_ip=request.remote_addr or "unknown", status="pending",
                                  recipient_protected=recipient_settings.protection_enabled)
        item.set_envelope(envelope)
        db.session.add(item)
        db.session.add(LabCapture(username=current_user.username, source_ip=request.remote_addr or "unknown",
                                  recipient=recipient.username, protection="plaintext",
                                  visible_content=body, wire_preview="HTML form payload held in Ubuntu lab relay",
                                  message_id=None, status="intercepted"))
        db.session.commit()
        log_event("message_intercepted", "warning", user=current_user,
                  detail=f"Message held for manual relay; intercept_id={item.id}; recipient={recipient.username}")
        flash("Message intercepted by the Ubuntu lab relay. It will not reach the recipient until the attacker forwards it.", "warning")
        return redirect(url_for("messaging.compose"))
    return _compose_page(form, 400 if form.errors else 200)


def _rows(box):
    from datetime import date
    from flask import abort
    filters = {key: request.args.get(key, "") for key in ("q", "sender", "recipient", "mode", "date_from", "date_to")}
    for key in ("date_from", "date_to"):
        if filters[key]:
            try:
                date.fromisoformat(filters[key])
            except ValueError:
                abort(400, description="Date filters must use YYYY-MM-DD.")
    pagination = messaging.mailbox_query(current_user, box, filters).paginate(
        page=request.args.get("page", 1, type=int), per_page=50, max_per_page=50, error_out=False)
    return ([messaging.summary(m, current_user) for m in pagination.items], pagination, filters,
            url_for(f"messaging.{box}", **{**filters, "page": pagination.prev_num}) if pagination.has_prev else None,
            url_for(f"messaging.{box}", **{**filters, "page": pagination.next_num}) if pagination.has_next else None)


@bp.get("/inbox")
@login_required
def inbox():
    rows, pagination, filters, prev_url, next_url = _rows("inbox")
    return render_template("inbox.html", rows=rows, pagination=pagination, filters=filters, prev_url=prev_url, next_url=next_url)


@bp.get("/sent")
@login_required
def sent():
    rows, pagination, filters, prev_url, next_url = _rows("sent")
    return render_template("sent.html", rows=rows, pagination=pagination, filters=filters, prev_url=prev_url, next_url=next_url)


@bp.get("/messages/<int:msg_id>")
@login_required
def detail(msg_id):
    msg = messaging.get_authorized_message(msg_id, current_user)
    result = messaging.open_message(msg, current_user)
    return render_template("message_detail.html", msg=msg, result=result,
                           env=msg.to_envelope())
