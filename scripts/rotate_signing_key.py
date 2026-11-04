#!/usr/bin/env python3
"""Explicitly rotate one account's Ed25519 signing key in persistent storage.

This is a recovery operation for an irretrievably missing/mismatched private
key. Messages signed with the previous key will no longer verify against the
account's updated public key. The default invocation is a dry run.
"""
import argparse
import hashlib
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def fingerprint(public_key):
    return hashlib.sha256(public_key.encode("ascii")).hexdigest()[:16]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-dir", default=str(ROOT / "instance" / "keys"),
                        help="directory containing the master key (aes_master.key)")
    parser.add_argument("--user-id", type=int, required=True,
                        help="database user ID whose signing key will be rotated")
    parser.add_argument("--apply", action="store_true", help="commit the key rotation")
    parser.add_argument("--confirm-invalidates-old-signatures", action="store_true",
                        help="acknowledge old signatures from this account will no longer verify")
    args = parser.parse_args()
    if args.apply and not args.confirm_invalidates_old_signatures:
        parser.error("--apply requires --confirm-invalidates-old-signatures")

    master_path = Path(args.key_dir).expanduser().resolve() / "aes_master.key"
    if not master_path.is_file():
        parser.error(f"master key file not found: {master_path}")
    master = master_path.read_bytes()
    if len(master) != 32:
        parser.error("master key is invalid; expected exactly 32 bytes")
    configured = os.environ.get("CNS_MASTER_KEY", "").strip()
    if configured:
        try:
            if bytes.fromhex(configured) != master:
                parser.error("CNS_MASTER_KEY does not match the selected key directory")
        except ValueError:
            parser.error("CNS_MASTER_KEY must be 64 hexadecimal characters")
    os.environ["CNS_MASTER_KEY"] = master.hex()

    from app import create_app
    from extensions import db
    from models import User, UserSigningKey, SecurityEvent
    from models.base import utcnow

    app = create_app()
    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            parser.error("DATABASE_URL must point to the deployment PostgreSQL database")
        user = db.session.get(User, args.user_id)
        if user is None:
            parser.error(f"database user id {args.user_id} does not exist")
        old_fingerprint = fingerprint(user.public_key)
        existing = db.session.get(UserSigningKey, args.user_id)
        if not args.apply:
            db.session.rollback()
            print(f"DRY RUN: would rotate user id {user.id} ({user.username}); "
                  f"old public-key fingerprint {old_fingerprint}; "
                  f"persistent key row {'exists' if existing else 'is missing'}.")
            print("Old messages signed by this account will no longer verify. No changes were written.")
            return

        if existing is not None:
            db.session.delete(existing)
            db.session.flush()
        new_public_key = app.extensions["cns_keys"].create_user_keypair(user.id)
        user.public_key = new_public_key
        user.session_epoch = int(user.session_epoch or 0) + 1
        db.session.add(SecurityEvent(
            created_at=utcnow(), event_type="signing_key_rotated", severity="critical",
            user_id=user.id, username=user.username, ip=None,
            detail=(f"Signing key explicitly rotated by maintenance script; "
                    f"old public-key fingerprint={old_fingerprint}; "
                    f"new public-key fingerprint={fingerprint(new_public_key)}; "
                    "prior signatures from this account no longer verify.")))
        db.session.commit()
        print(f"[OK] signing key rotated for user id {user.id} ({user.username}); "
              "all existing sessions were invalidated.")


if __name__ == "__main__":
    main()
