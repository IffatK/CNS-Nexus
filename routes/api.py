from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user, login_required
from flask_wtf.csrf import generate_csrf

from extensions import db
from models import User, LabSettings, LabCapture, InterceptedMessage
from services import messaging
from services.crypto import (ALG, CryptoError, Envelope, SignatureError, b64d, b64e, public_key_from_b64,
                             verify_envelope)
from services.health import health
from services.messaging import MessagingError
from services.keys import KeyManagerError
from services.security_log import log_event
from services.transport_crypto import public_key_json, decrypt_payload

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.get("/health")
def api_health():
    h = health()
    return jsonify(h), (200 if h["status"] == "ok" else 503)


@bp.get("/csrf")
def csrf_token():
    return jsonify(csrf_token=generate_csrf())


@bp.get("/me")
@login_required
def me():
    return jsonify(id=current_user.id, username=current_user.username, is_admin=current_user.is_admin,
                   public_key=current_user.public_key)


@bp.get("/stats")
@login_required
def stats():
    from routes.dashboard import dashboard_data
    d = dashboard_data(current_user)
    return jsonify({k: d[k] for k in ("users", "inbox", "sent", "verified", "unprotected", "failed", "event_total", "critical")})


@bp.get("/messages")
@login_required
def list_messages():
    box = request.args.get("box", "inbox")
    if box not in ("inbox", "sent"):
        return jsonify(error="box must be inbox or sent"), 400
    return jsonify(messages=[messaging.summary(m, current_user) for m in messaging.mailbox(current_user, box)])


@bp.post("/messages")
@login_required
def send():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(error="JSON object body required"), 400
    setting = LabSettings.query.filter_by(user_id=current_user.id).first()
    if setting and setting.protection_enabled:
        return jsonify(error="Protection is enabled; use the protected transport endpoint."), 409
    try:
        msg = messaging.send_message(current_user, data.get("recipient"), data.get("body"))
    except MessagingError as e:
        return jsonify(error=e.message), e.status
    return jsonify(id=msg.id, uuid=msg.msg_uuid, created_at=msg.created_at), 201


@bp.get("/messages/<int:msg_id>")
@login_required
def get_message(msg_id):
    msg = messaging.get_authorized_message(msg_id, current_user)
    res = messaging.open_message(msg, current_user)
    out = messaging.summary(msg, current_user, with_status=False)
    out.update(verification=res["status"], body=res["plaintext"])
    if current_user.id == msg.recipient_id and msg.relay_report:
        out.update(relay_report=True, relay_ip=msg.relay_ip,
                   relay_tampered=msg.protection == "plaintext_relay_tampered")
    return jsonify(out)



@bp.get("/transport/public-key")
@login_required
def transport_public_key():
    return jsonify(public_key_json())


@bp.get("/transport/settings")
@login_required
def transport_settings():
    row = LabSettings.query.filter_by(user_id=current_user.id).first()
    if row is None:
        row = LabSettings(user_id=current_user.id, protection_enabled=False)
        db.session.add(row)
        db.session.commit()
    recipient_name = (request.args.get("recipient") or "").strip().lower()
    target = messaging.find_user(recipient_name, current_user) if recipient_name else None
    target_settings = LabSettings.query.filter_by(user_id=target.id).first() if target else None
    recipient_enabled = bool(target_settings and target_settings.protection_enabled)
    out = {"protection_enabled": bool(row.protection_enabled), "recipient_enabled": recipient_enabled,
           "both_enabled": bool(row.protection_enabled and recipient_enabled),
           "policy_mismatch": False,
           "delivery_mode": "protected" if row.protection_enabled else "plaintext_relay",
           "will_intercept": not bool(row.protection_enabled)}
    if row.protection_enabled:
        out["server_host"] = request.host
    return jsonify(out)


@bp.post("/lab/send-plain")
@login_required
def lab_send_plain():
    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("recipient"), str) or not isinstance(data.get("body"), str):
        return jsonify(error="recipient and body are required"), 400
    recipient = data["recipient"].strip().lower()
    body = data["body"]
    if not body.strip():
        return jsonify(error="Message body is empty"), 400
    if len(body) > 2000:
        return jsonify(error="Message too long (max 2000 characters)"), 400
    target = messaging.find_user(recipient, current_user)
    if target is None:
        return jsonify(error="Recipient not found"), 404
    sender_settings = LabSettings.query.filter_by(user_id=current_user.id).first()
    target_settings = LabSettings.query.filter_by(user_id=target.id).first()
    sender_protected = bool(sender_settings and sender_settings.protection_enabled)
    recipient_protected = bool(target_settings and target_settings.protection_enabled)
    allowed, reason = messaging.plaintext_relay_policy(sender_protected, recipient_protected)
    if not allowed:
        log_event("plaintext_transport_blocked", "warning", user=current_user,
                  detail=f"Plaintext relay blocked for recipient={target.username}; sender_protected={sender_protected}; recipient_protected={recipient_protected}")
        return jsonify(error=reason), 409
    try:
        envelope = messaging.prepare_intercepted_envelope(current_user, target.username, body)
    except MessagingError as e:
        return jsonify(error=e.message), e.status
    except KeyManagerError as exc:
        db.session.rollback()
        # The exception text distinguishes a missing DB row from a wrong
        # Render CNS_MASTER_KEY, without logging any secret or message body.
        current_app.logger.error("Signing key unavailable for user id %s: %s",
                                 current_user.id, exc)
        log_event("signing_key_unavailable", "critical", user=current_user,
                  detail="Plaintext relay could not load the sender signing key; no message was queued")
        return jsonify(error=("This account's signing key is unavailable on the server. Restore the original "
                              "persistent key files before sending; do not regenerate keys or re-register.")), 503
    item = InterceptedMessage(sender_username=current_user.username, recipient_username=target.username,
                              original_body=body, source_ip=request.remote_addr or "unknown", status="pending",
                              recipient_protected=recipient_protected)
    item.set_envelope(envelope)
    db.session.add(item)
    db.session.add(LabCapture(username=current_user.username, source_ip=request.remote_addr or "unknown",
                              recipient=target.username, protection="plaintext", visible_content=body,
                              wire_preview="Plaintext held in attacker-controlled lab relay", message_id=None, status="intercepted"))
    db.session.commit()
    log_event("message_intercepted", "warning", user=current_user,
              detail=f"Message held for manual relay editing; intercept_id={item.id}; recipient={target.username}")
    return jsonify(id=item.id, created_at=item.created_at, protection="plaintext", intercepted=True,
                   message="Held by lab relay; attacker must forward it before recipient receives it."), 201


@bp.post("/lab/send-protected")
@login_required
def lab_send_protected():
    data = request.get_json(silent=True)
    required = ("recipient", "elgamal_c1", "elgamal_c2", "nonce", "ciphertext")
    if not isinstance(data, dict) or any(not isinstance(data.get(k), str) for k in required):
        return jsonify(error="encrypted payload fields required"), 400
    setting = LabSettings.query.filter_by(user_id=current_user.id).first()
    if not setting or not setting.protection_enabled:
        return jsonify(error="Enable protection in Settings before sending protected messages."), 409
    recipient = data["recipient"].strip().lower()
    target = messaging.find_user(recipient, current_user)
    if target is None:
        return jsonify(error="Recipient not found"), 404
    # Protection follows the sender's choice. The server delivers to recipients
    # regardless of their local preference. An unprotected sender instead
    # enters the readable attacker relay even when the receiver opted in.
    try:
        body = decrypt_payload(data)
    except Exception:
        log_event("transport_decrypt_failed", "critical", user=current_user,
                  detail="Protected transport payload failed authentication/decryption")
        return jsonify(error="Protected payload rejected: decryption/authentication failed"), 400
    try:
        msg = messaging.send_message(current_user, recipient, body)
    except MessagingError as e:
        return jsonify(error=e.message), e.status
    preview = f'ElGamal c1={data["elgamal_c1"][:24]}… c2={data["elgamal_c2"][:24]}…; AES-GCM ciphertext={len(data["ciphertext"])} base64 chars'
    capture = LabCapture(username=current_user.username, source_ip=request.remote_addr or "unknown",
                         recipient=recipient, protection="protected", visible_content=None,
                         wire_preview=preview, message_id=msg.id, status="accepted")
    db.session.add(capture)
    db.session.commit()
    log_event("lab_payload_protected", "info", user=current_user,
              detail=f"Protected transport payload received; msg={msg.id}; content not visible in capture")
    return jsonify(id=msg.id, created_at=msg.created_at, protection="protected", server_host=request.host), 201


def envelope_json(msg):
    e = msg.to_envelope()
    return {"msg_id": e.msg_uuid, "sender_id": e.sender_id, "recipient_id": e.recipient_id,
            "created_at": e.created_at, "alg": e.alg, "nonce": b64e(e.nonce),
            "ciphertext": b64e(e.ciphertext), "signature": b64e(e.signature)}


@bp.get("/messages/<int:msg_id>/envelope")
@login_required
def get_envelope(msg_id):
    msg = messaging.get_authorized_message(msg_id, current_user)
    return jsonify(envelope_json(msg))


@bp.post("/verify")
@login_required
def verify():
    """Signature-only verification oracle (never decrypts). Used by Kali tamper tests."""
    d = request.get_json(silent=True)
    need = ("msg_id", "sender_id", "recipient_id", "created_at", "alg", "nonce", "ciphertext", "signature")
    if not isinstance(d, dict) or any(k not in d for k in need):
        return jsonify(error="envelope fields required: " + ", ".join(need)), 400
    try:
        if not (isinstance(d["sender_id"], int) and isinstance(d["recipient_id"], int)
                and all(isinstance(d[k], str) for k in ("msg_id", "created_at", "alg", "nonce", "ciphertext", "signature"))):
            raise CryptoError("wrong field types")
        sender = db.session.get(User, d["sender_id"])
        if sender is None:
            raise CryptoError("unknown sender")
        env = Envelope(d["msg_id"], d["sender_id"], d["recipient_id"], d["created_at"], d["alg"],
                       b64d(d["nonce"]), b64d(d["ciphertext"]), b64d(d["signature"]))
        verify_envelope(env, public_key_from_b64(sender.public_key))
    except SignatureError as e:
        log_event("crypto_failure", "critical", user=current_user, detail=f"/api/verify rejected envelope: {e}")
        return jsonify(valid=False, reason=str(e)), 200
    except CryptoError as e:
        log_event("crypto_failure", "warning", user=current_user, detail=f"/api/verify malformed envelope: {e}")
        return jsonify(valid=False, reason=str(e)), 200
    log_event("envelope_verify", "info", user=current_user, detail="/api/verify envelope valid")
    return jsonify(valid=True, reason="signature verified")
