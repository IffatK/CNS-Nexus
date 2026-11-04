import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import flask
from flask import current_app
from sqlalchemy import text
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from extensions import db
from models import LoginAttempt, Message, SecurityEvent, User
from services.crypto import public_key_b64

VERSION = "1.0.0"


def key_manager_check():
    """Check the active master and wrapped signing keys without changing files.

    This validates the key/database pairing but does not claim historical
    message ciphertext can be decrypted.
    """
    manager = current_app.extensions["cns_keys"]
    file_status = manager.status()
    checked = 0
    pairings_ok = True
    try:
        nonce = os.urandom(12)
        probe = b"cns-key-manager-health-check"
        encrypted = AESGCM(manager.master_key).encrypt(nonce, probe, b"health-check")
        pairings_ok = AESGCM(manager.master_key).decrypt(nonce, encrypted, b"health-check") == probe
        for user in User.query.order_by(User.id).all():
            private_key = manager.load_private(user.id)
            if public_key_b64(private_key) != user.public_key:
                pairings_ok = False
            checked += 1
        if checked != file_status["user_keys"]:
            pairings_ok = False
    except Exception:
        pairings_ok = False

    operational = file_status["master_present"] and pairings_ok
    if not operational:
        state = "FAILED"
    elif file_status["permissions_ok"] is not True:
        state = "DEGRADED"
    else:
        state = "HEALTHY"
    return {"state": state, "master_present": file_status["master_present"],
            "permissions_checked": file_status["permissions_checked"],
            "permissions_ok": file_status["permissions_ok"],
            "user_keys_checked": checked, "user_key_count": file_status["user_keys"],
            "key_pairings_ok": pairings_ok, "stored_messages_checked": False}


def health():
    """Operational checks for the database and actual configured key manager."""
    out = {"status": "ok", "version": VERSION, "time": datetime.now(timezone.utc).isoformat()}
    try:
        db.session.execute(text("SELECT 1"))
        User.query.count()  # proves schema exists
        out["database"] = "ok"
    except Exception:
        db.session.rollback()
        out["database"] = "error"
        out["status"] = "degraded"
    out["key_check"] = key_manager_check()
    out["keys"] = "ok" if out["key_check"]["state"] == "HEALTHY" else "degraded"
    if out["keys"] != "ok":
        out["status"] = "degraded"
    return out


def system_status():
    h = health()
    if db.engine.dialect.name == "sqlite":
        uri = current_app.config["SQLALCHEMY_DATABASE_URI"]
        dbfile = Path(uri.replace("sqlite:///", "", 1))
        db_path = str(dbfile)
        db_bytes = dbfile.stat().st_size if dbfile.exists() else 0
    else:
        # Never return a remote connection URL: it may contain credentials.
        db_path = "PostgreSQL (remote)"
        db_bytes = 0
    counts = {"users": User.query.count(), "messages": Message.query.count(),
              "security_events": SecurityEvent.query.count(), "login_attempts": LoginAttempt.query.count()}
    return {"health": h, "counts": counts, "key_status": current_app.extensions["cns_keys"].status(),
            "db_path": db_path, "db_bytes": db_bytes,
            "python": sys.version.split()[0], "flask": flask.__version__}
