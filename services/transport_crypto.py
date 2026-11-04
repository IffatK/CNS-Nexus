"""Lab transport demo: ElGamal key encapsulation + AES-256-GCM payload encryption.

This is a teaching implementation, not a production protocol. ElGamal protects the
message payload in transit from passive network observers; the server holds the
private exponent and can decrypt, so this is NOT end-to-end encryption.
"""
import base64, os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# RFC 3526 group 5 (1536-bit prime; educational demo only), generator 2.
P = int("".join("""FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DD
EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245
E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D
C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F
83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF""".split()), 16)
G = 2
AAD_PREFIX = "CNS-LAB-TRANSPORT-V1"

def _key_path():
    from flask import current_app
    return Path(current_app.config["KEY_DIR"]) / "elgamal_private.hex"

def private_x():
    p = _key_path()
    from flask import current_app
    manager = current_app.extensions["cns_keys"]
    if manager.database_backed:
        from sqlalchemy.exc import IntegrityError
        from extensions import db
        from models import Message
        from models.key_material import ApplicationKeyMaterial
        record = db.session.get(ApplicationKeyMaterial, "transport_elgamal")
        if record is None:
            # Migrate the existing local transport key on first use when it is
            # present. Never silently rotate it if protected messages exist.
            if p.is_file():
                try:
                    value = int(p.read_text(encoding="ascii").strip(), 16)
                    raw = value.to_bytes(192, "big")
                except (ValueError, OverflowError, OSError) as exc:
                    raise RuntimeError("The existing transport key file is invalid; restore it from backup.") from exc
            else:
                if Message.query.filter_by(protection="protected").count():
                    raise RuntimeError("The transport key is missing; restore the original key to open existing protected messages.")
                value = int.from_bytes(os.urandom(192), "big") % (P - 2) + 2
                raw = value.to_bytes(192, "big")
            nonce = os.urandom(12)
            encrypted = nonce + AESGCM(manager.master_key).encrypt(
                nonce, raw, b"cns-application-key:transport_elgamal")
            record = ApplicationKeyMaterial(name="transport_elgamal", encrypted_value=encrypted)
            db.session.add(record)
            try:
                db.session.commit()
            except IntegrityError:
                # Another worker initialized the singleton key at the same time.
                db.session.rollback()
                record = db.session.get(ApplicationKeyMaterial, "transport_elgamal")
                if record is None:
                    raise RuntimeError("Could not initialize persistent transport key storage.")
        try:
            blob = bytes(record.encrypted_value)
            raw = AESGCM(manager.master_key).decrypt(
                blob[:12], blob[12:], b"cns-application-key:transport_elgamal")
            if len(raw) != 192:
                raise ValueError("invalid key length")
            value = int.from_bytes(raw, "big")
            if not 1 < value < P - 1:
                raise ValueError("invalid key value")
            return value
        except Exception as exc:
            raise RuntimeError("The persistent transport key failed its integrity check.") from exc
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        x = int.from_bytes(os.urandom(192), "big") % (P - 2) + 2
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as f: f.write(format(x, "x"))
    return int(p.read_text(encoding="ascii").strip(), 16)

def public_y():
    return pow(G, private_x(), P)

def public_key_json():
    return {"p": format(P, "x"), "g": format(G, "x"), "y": format(public_y(), "x"),
            "algorithm": "ElGamal KEM + AES-256-GCM", "aad": AAD_PREFIX}

def b64d(s):
    return base64.b64decode(s.encode("ascii"), validate=True)

def b64e(b):
    return base64.b64encode(b).decode("ascii")

def decrypt_payload(d):
    c1 = int(d["elgamal_c1"], 16)
    c2 = int(d["elgamal_c2"], 16)
    if not (1 < c1 < P - 1 and 1 < c2 < P):
        raise ValueError("invalid ElGamal ciphertext")
    x = private_x()
    shared = pow(c1, x, P)
    key_int = (c2 * pow(shared, -1, P)) % P
    key = key_int.to_bytes(32, "big")
    nonce = b64d(d["nonce"])
    ciphertext = b64d(d["ciphertext"])
    if len(nonce) != 12:
        raise ValueError("invalid AES-GCM nonce")
    return AESGCM(key).decrypt(nonce, ciphertext, (AAD_PREFIX + "|" + d["recipient"].strip().lower()).encode("utf-8")).decode("utf-8")
