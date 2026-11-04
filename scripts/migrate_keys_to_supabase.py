#!/usr/bin/env python3
"""Validate and migrate local CNS keys into the configured Supabase database.

The exact original 32-byte master key remains an environment secret. Per-user
signing keys and the transport private key are stored encrypted in Postgres.
Run once with --apply after DATABASE_URL points to the deployment database.
"""
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-dir", default=str(ROOT / "instance" / "keys"),
                        help="directory containing the original aes_master.key and users/*.wrapped")
    parser.add_argument("--apply", action="store_true", help="write validated keys to the configured database")
    args = parser.parse_args()
    key_dir = Path(args.key_dir).expanduser().resolve()
    master_path = key_dir / "aes_master.key"
    if not master_path.is_file():
        parser.error(f"original master key not found: {master_path}")
    master = master_path.read_bytes()
    if len(master) != 32:
        parser.error("original master key is invalid; expected 32 bytes")
    configured = os.environ.get("CNS_MASTER_KEY", "").strip()
    if configured:
        try:
            if bytes.fromhex(configured) != master:
                parser.error("CNS_MASTER_KEY does not match the selected original key directory")
        except ValueError:
            parser.error("CNS_MASTER_KEY must be 64 hexadecimal characters")
    # Set before importing config/app so KeyManager selects database-backed mode.
    os.environ["CNS_MASTER_KEY"] = master.hex()

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from app import create_app
    from extensions import db
    from models import Message, User, UserSigningKey, ApplicationKeyMaterial
    from services.crypto import public_key_b64
    from services.transport_crypto import P

    app = create_app()
    source_keys = key_dir / "users"
    master_aes = AESGCM(master)
    pending = []
    with app.app_context():
        if db.engine.dialect.name != "postgresql":
            parser.error("DATABASE_URL must point to the Supabase PostgreSQL database before migrating keys")
        users = {int(user.id): user for user in User.query.order_by(User.id).all()}
        existing = {int(row.user_id): row for row in UserSigningKey.query.all()}
        files = {}
        if source_keys.is_dir():
            for path in source_keys.glob("*.ed25519.wrapped"):
                try:
                    uid = int(path.name.split(".", 1)[0])
                except ValueError:
                    continue
                files[uid] = path

        for uid, user in users.items():
            if uid in files:
                blob = files[uid].read_bytes()
                if len(blob) < 29:
                    parser.error(f"wrapped signing key for database user id {uid} is truncated")
                try:
                    raw = master_aes.decrypt(blob[:12], blob[12:], f"cns-user-key:{uid}".encode())
                    private = Ed25519PrivateKey.from_private_bytes(raw)
                except Exception:
                    parser.error(f"backup signing key for database user id {uid} does not decrypt with this master key")
                if public_key_b64(private) != user.public_key:
                    parser.error(f"backup signing key for database user id {uid} does not match its database public key")
                current = existing.get(uid)
                if current is not None and bytes(current.wrapped_key) != blob:
                    parser.error(f"database already has a different signing key for user id {uid}; refusing to overwrite")
                if current is None:
                    pending.append(UserSigningKey(user_id=uid, wrapped_key=blob))
            elif uid in existing:
                try:
                    private = app.extensions["cns_keys"].load_private(uid)
                except Exception:
                    parser.error(f"persistent signing key for database user id {uid} failed validation")
                if public_key_b64(private) != user.public_key:
                    parser.error(f"persistent signing key for database user id {uid} does not match its public key")
            else:
                parser.error(f"no original signing key found for database user id {uid} ({user.username})")

        transport_path = key_dir / "elgamal_private.hex"
        transport_row = db.session.get(ApplicationKeyMaterial, "transport_elgamal")
        transport_blob = None
        if transport_path.is_file():
            try:
                value = int(transport_path.read_text(encoding="ascii").strip(), 16)
                if not 1 < value < P - 1:
                    raise ValueError
                raw = value.to_bytes(192, "big")
            except (ValueError, OverflowError):
                parser.error("transport private key is malformed")
            if transport_row is not None:
                encrypted = bytes(transport_row.encrypted_value)
                try:
                    saved = master_aes.decrypt(encrypted[:12], encrypted[12:], b"cns-application-key:transport_elgamal")
                except Exception:
                    parser.error("persistent transport private key does not decrypt with this master key")
                if saved != raw:
                    parser.error("database already has a different transport key; refusing to overwrite")
            else:
                nonce = os.urandom(12)
                encrypted = nonce + master_aes.encrypt(nonce, raw, b"cns-application-key:transport_elgamal")
                transport_blob = ApplicationKeyMaterial(name="transport_elgamal", encrypted_value=encrypted)
        elif transport_row is None and Message.query.filter_by(protection="protected").count():
            parser.error("protected messages exist but this backup has no transport private key")

        if args.apply:
            db.session.add_all(pending)
            if transport_blob is not None:
                db.session.add(transport_blob)
            db.session.commit()
            print(f"[OK] migrated {len(pending)} signing key(s); transport key "
                  f"{'migrated' if transport_blob is not None else 'already present or not needed'}.")
        else:
            db.session.rollback()
            print(f"[OK] validation passed for {len(users)} account(s); {len(pending)} signing key(s) ready to migrate. "
                  "No keys were written. Re-run with --apply to persist them.")


if __name__ == "__main__":
    main()
