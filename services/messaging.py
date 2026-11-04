"""Send / open / verify messages. All routes and the API go through here (one code path)."""
from flask import current_app
from werkzeug.exceptions import NotFound
from sqlalchemy import or_

from extensions import db
from models.message import Message
from models.user import User
from services import rate_limit
from services.crypto import (CryptoError, DecryptionError, SignatureError, decrypt_envelope, decrypt_unprotected,
                             encrypt_and_sign,
                             public_key_from_b64, reencrypt_without_resigning, verify_envelope)
from services.security_log import log_event
from services.roles import client_users, is_admin_identity


class MessagingError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message, self.status = message, status


def plaintext_relay_policy(sender_protected, recipient_protected):
    """Authoritative server policy for the deliberately readable lab relay."""
    sender_protected = bool(sender_protected)
    if sender_protected:
        return False, "Sender-side protection is enabled; use the protected transport endpoint."
    return True, ("Sender-side protection is off; the readable lab relay can inspect and modify this message."
                  if recipient_protected else "Both accounts are unprotected; the readable lab relay can inspect and modify this message.")


def keys():
    return current_app.extensions["cns_keys"]


def find_user(username, sender=None):
    if not isinstance(username, str):
        return None
    query = User.query.filter_by(username=username.strip().lower())
    # Client accounts never discover or address admin accounts. Admin
    # operators may still address ordinary client accounts when needed.
    if sender is None or not is_admin_identity(sender):
        query = client_users(query)
    return query.first()


def send_message(sender, recipient_username, body, protection="protected"):
    if not isinstance(recipient_username, str) or not isinstance(body, str):
        raise MessagingError("'recipient' and 'body' must be strings", 400)
    if not body.strip():
        raise MessagingError("Message body is empty", 400)
    if len(body) > current_app.config["MAX_MESSAGE_CHARS"]:
        raise MessagingError(f"Message too long (max {current_app.config['MAX_MESSAGE_CHARS']} characters)", 400)
    recipient = find_user(recipient_username, sender)
    if recipient is None:
        log_event("message_rejected", "info", user=sender, detail="unknown recipient")
        raise MessagingError("Recipient not found", 404)
    if rate_limit.send_throttled(sender.id):
        log_event("rate_limited", "warning", user=sender, detail="message send throttled")
        raise MessagingError("Too many messages; slow down", 429)
    if protection == "plaintext_relay":
        env = encrypt_unprotected(keys().master_key, sender.id, recipient.id, body)
    else:
        priv = keys().load_private(sender.id)
        env = encrypt_and_sign(keys().master_key, priv, sender.id, recipient.id, body)
    msg = Message.from_envelope(env)
    if protection not in ("protected", "plaintext_relay"):
        raise MessagingError("Invalid message protection mode", 400)
    msg.protection = protection
    db.session.add(msg)
    db.session.commit()
    log_event("message_sent", "info", user=sender,
              detail=f"msg={msg.id} recipient_id={recipient.id} plaintext_bytes={len(body.encode('utf-8'))}")
    return msg


def prepare_intercepted_envelope(sender, recipient_username, body):
    """Sign once at the sender's submit step; the attacker relay never receives a signer."""
    if not isinstance(recipient_username, str) or not isinstance(body, str) or not body.strip():
        raise MessagingError("'recipient' and non-empty 'body' are required", 400)
    if len(body) > current_app.config["MAX_MESSAGE_CHARS"]:
        raise MessagingError(f"Message too long (max {current_app.config['MAX_MESSAGE_CHARS']} characters)", 400)
    recipient = find_user(recipient_username, sender)
    if recipient is None:
        raise MessagingError("Recipient not found", 404)
    if rate_limit.send_throttled(sender.id):
        log_event("rate_limited", "warning", user=sender, detail="message send throttled")
        raise MessagingError("Too many messages; slow down", 429)
    private_key = keys().load_private(sender.id)
    return encrypt_and_sign(keys().master_key, private_key, sender.id, recipient.id, body)


def envelope_for_edit(original, edited_body):
    return reencrypt_without_resigning(keys().master_key, original, edited_body)


def get_authorized_message(msg_id, viewer):
    """404 for both 'missing' and 'not yours' (no existence oracle); denial is logged."""
    msg = db.session.get(Message, msg_id)
    if msg is None:
        raise NotFound()
    if viewer.id not in (msg.sender_id, msg.recipient_id):
        log_event("access_denied", "warning", user=viewer, detail=f"IDOR attempt on message {msg_id}")
        raise NotFound()
    if not is_admin_identity(viewer):
        counterpart = msg.recipient if msg.sender_id == viewer.id else msg.sender
        if is_admin_identity(counterpart):
            raise NotFound()
    return msg


def verify_signature_status(msg):
    if msg.protection == "plaintext_relay":
        # This mode explicitly makes no sender-authenticity promise. The relay
        # may replace the body and produce a fresh storage-only AEAD envelope.
        return "unprotected"
    sender = db.session.get(User, msg.sender_id)
    if sender is None:
        return "malformed"
    try:
        verify_envelope(msg.to_envelope(), public_key_from_b64(sender.public_key))
        return "verified"
    except SignatureError:
        return "signature_invalid"
    except CryptoError:
        return "malformed"


def open_message(msg, viewer):
    """Verify signature, then decrypt. Plaintext is None unless both succeed."""
    if viewer.id not in (msg.sender_id, msg.recipient_id):
        log_event("access_denied", "warning", user=viewer, detail=f"open_message denied msg={msg.id}")
        raise NotFound()
    try:
        sender = db.session.get(User, msg.sender_id)
        if sender is None:
            raise CryptoError("sender key unavailable")
        pub = public_key_from_b64(sender.public_key)
        if msg.protection == "plaintext_relay":
            envelope = msg.to_envelope()
            plaintext = (decrypt_envelope(keys().master_key, envelope, pub) if envelope.signature
                         else decrypt_unprotected(keys().master_key, envelope))
            log_event("message_read_unprotected", "warning", user=viewer,
                      detail=f"msg={msg.id} body traveled through readable relay; sender authenticity is not guaranteed")
            return {"status": "unprotected", "plaintext": plaintext}
        plaintext = decrypt_envelope(keys().master_key, msg.to_envelope(), pub)
        log_event("message_read", "info", user=viewer, detail=f"msg={msg.id} signature=verified aead=ok")
        return {"status": "verified", "plaintext": plaintext}
    except SignatureError:
        log_event("crypto_failure", "critical", user=viewer, detail=f"msg={msg.id} signature verification FAILED")
        return {"status": "signature_invalid", "plaintext": None}
    except DecryptionError:
        log_event("crypto_failure", "critical", user=viewer, detail=f"msg={msg.id} AES-GCM authentication FAILED")
        return {"status": "decryption_failed", "plaintext": None}
    except CryptoError:
        log_event("crypto_failure", "critical", user=viewer, detail=f"msg={msg.id} malformed envelope")
        return {"status": "malformed", "plaintext": None}


def summary(msg, viewer, with_status=True):
    return {
        "id": msg.id, "uuid": msg.msg_uuid, "created_at": msg.created_at,
        "sender": msg.sender.username, "recipient": msg.recipient.username,
        "direction": "sent" if msg.sender_id == viewer.id else "received",
        "verification": verify_signature_status(msg) if with_status else None,
        "protection": msg.protection,
    }


def mailbox(viewer, box, limit=100):
    col = Message.recipient_id if box == "inbox" else Message.sender_id
    query = Message.query.filter(col == viewer.id)
    if not is_admin_identity(viewer):
        counterpart_id = Message.sender_id if box == "inbox" else Message.recipient_id
        query = query.join(User, counterpart_id == User.id)
        query = client_users(query)
    return query.order_by(Message.id.desc()).limit(limit).all()


def mailbox_query(viewer, box, filters=None):
    """Filter metadata using SQL; ciphertext contents are intentionally not searched."""
    filters = filters or {}
    col = Message.recipient_id if box == "inbox" else Message.sender_id
    query = Message.query.filter(col == viewer.id)
    if not is_admin_identity(viewer):
        counterpart_id = Message.sender_id if box == "inbox" else Message.recipient_id
        query = query.join(User, counterpart_id == User.id)
        query = client_users(query)
    term = (filters.get("q") or "").strip()[:100]
    if term:
        pattern = f"%{term}%"
        query = query.filter(or_(
            Message.msg_uuid.ilike(pattern), Message.sender.has(User.username.ilike(pattern)),
            Message.recipient.has(User.username.ilike(pattern))))
    sender = (filters.get("sender") or "").strip().lower()[:32]
    recipient = (filters.get("recipient") or "").strip().lower()[:32]
    if sender:
        query = query.filter(Message.sender.has(User.username == sender))
    if recipient:
        query = query.filter(Message.recipient.has(User.username == recipient))
    mode = filters.get("mode")
    if mode in ("protected", "plaintext_relay"):
        query = query.filter(Message.protection == mode)
    date_from, date_to = filters.get("date_from"), filters.get("date_to")
    if date_from:
        query = query.filter(Message.created_at >= date_from + "T")
    if date_to:
        query = query.filter(Message.created_at < date_to + "T\uffff")
    return query.order_by(Message.id.desc())
