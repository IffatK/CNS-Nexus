"""Key management. Master AES key + per-user Ed25519 private keys (wrapped with the master key).

Files live in instance/keys/ (dir 0700, files 0600). Keys are NEVER regenerated silently:
a missing master key is a hard error unless explicit init (scripts/init_db.py) or the test-only auto_init flag.
"""
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from services.crypto import public_key_b64

MASTER_NAME = "aes_master.key"


class KeyManagerError(RuntimeError):
    pass


class KeyManager:
    def __init__(self, key_dir, auto_init=False):
        self.key_dir = Path(key_dir)
        self.users_dir = self.key_dir / "users"
        configured_master = os.environ.get("CNS_MASTER_KEY", "").strip()
        self.database_backed = bool(configured_master)
        if self.database_backed:
            try:
                data = bytes.fromhex(configured_master)
            except ValueError as exc:
                raise KeyManagerError("CNS_MASTER_KEY must be the 64-character hexadecimal master key.") from exc
            if len(data) != 32:
                raise KeyManagerError("CNS_MASTER_KEY must decode to exactly 32 bytes.")
            self._master = data
            return
        master = self.key_dir / MASTER_NAME
        if not master.exists():
            has_user_keys = self.users_dir.is_dir() and any(self.users_dir.iterdir())
            if has_user_keys:
                raise KeyManagerError(f"Master key {master} is missing but user key files exist. "
                                      "Refusing to regenerate. Restore it from backup.")
            if not auto_init:
                raise KeyManagerError(f"Master key not found at {master}. Run: python3 scripts/init_db.py")
            self.initialize(self.key_dir)
        data = master.read_bytes()
        if len(data) != 32:
            raise KeyManagerError(f"Master key file {master} is corrupt (expected 32 bytes).")
        self._master = data

    @staticmethod
    def initialize(key_dir):
        key_dir = Path(key_dir)
        key_dir.mkdir(parents=True, exist_ok=True)
        (key_dir / "users").mkdir(exist_ok=True)
        for d in (key_dir, key_dir / "users"):
            os.chmod(d, 0o700)
        master = key_dir / MASTER_NAME
        fd = os.open(master, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)  # O_EXCL: never overwrite
        with os.fdopen(fd, "wb") as f:
            f.write(os.urandom(32))
        return master

    @property
    def master_key(self) -> bytes:
        return self._master

    def _user_path(self, user_id):
        return self.users_dir / f"{int(user_id)}.ed25519.wrapped"

    @staticmethod
    def _aad(user_id):
        return f"cns-user-key:{int(user_id)}".encode()

    def create_user_keypair(self, user_id) -> str:
        priv = Ed25519PrivateKey.generate()
        raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
        nonce = os.urandom(12)
        blob = nonce + AESGCM(self._master).encrypt(nonce, raw, self._aad(user_id))
        if self.database_backed:
            from extensions import db
            from models.key_material import UserSigningKey
            db.session.add(UserSigningKey(user_id=int(user_id), wrapped_key=blob))
            # Preserve the filesystem backend's create-once behavior: reject
            # orphaned IDs instead of ever replacing an existing account key.
            db.session.flush()
        else:
            self.users_dir.mkdir(exist_ok=True)
            fd = os.open(self._user_path(user_id), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
        return public_key_b64(priv)

    def load_private(self, user_id) -> Ed25519PrivateKey:
        if self.database_backed:
            from extensions import db
            from models.key_material import UserSigningKey
            row = db.session.get(UserSigningKey, int(user_id))
            if row is None:
                raise KeyManagerError(f"Private key for user {user_id} not found in persistent key storage.")
            blob = bytes(row.wrapped_key)
        else:
            p = self._user_path(user_id)
            if not p.exists():
                raise KeyManagerError(f"Private key for user {user_id} not found (not regenerating).")
            blob = p.read_bytes()
        try:
            raw = AESGCM(self._master).decrypt(blob[:12], blob[12:], self._aad(user_id))
        except Exception as exc:
            raise KeyManagerError(f"Private key file for user {user_id} failed integrity check.") from exc
        return Ed25519PrivateKey.from_private_bytes(raw)

    def delete_user_key(self, user_id):
        """Only used to roll back a failed registration."""
        if self.database_backed:
            from extensions import db
            from models.key_material import UserSigningKey
            db.session.query(UserSigningKey).filter_by(user_id=int(user_id)).delete(synchronize_session=False)
            return
        try:
            self._user_path(user_id).unlink()
        except FileNotFoundError:
            pass

    def status(self) -> dict:
        if self.database_backed:
            from extensions import db
            from models.key_material import UserSigningKey
            return {"master_present": True, "permissions_checked": False,
                    "permissions_ok": True, "user_keys": UserSigningKey.query.count(),
                    "storage": "database"}
        master = self.key_dir / MASTER_NAME
        # POSIX mode bits are meaningful on Ubuntu. Windows mode bits do not
        # represent effective ACLs, so report that review as unknown.
        permissions_checked = os.name != "nt"
        mode_ok = None
        if permissions_checked:
            try:
                paths = [master, self.key_dir, self.users_dir]
                mode_ok = master.is_file() and self.users_dir.is_dir() and all(
                    (p.stat().st_mode & 0o077) == 0 for p in paths
                ) and all((p.stat().st_mode & 0o077) == 0
                          for p in self.users_dir.glob("*.wrapped"))
            except OSError:
                mode_ok = False
        n = len(list(self.users_dir.glob("*.wrapped"))) if self.users_dir.is_dir() else 0
        return {"master_present": master.is_file(), "permissions_checked": permissions_checked,
                "permissions_ok": mode_ok, "user_keys": n}
