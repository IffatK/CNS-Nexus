#!/usr/bin/env python3
"""Safe, idempotent initialisation. Never overwrites or deletes existing data/keys.
 - creates .env with a random SECRET_KEY if absent
 - backs up any existing DB/keys before touching anything
 - creates the master AES key only if absent (refuses if DB already has users but keys are missing)
 - creates missing tables only; aborts if an existing table has a different schema"""
import argparse
import os
import secrets
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--instance-dir")
    args = ap.parse_args()
    if args.instance_dir:
        os.environ["CNS_INSTANCE_DIR"] = args.instance_dir

    env = ROOT / ".env"
    if not env.exists():
        fd = os.open(env, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"SECRET_KEY={secrets.token_hex(32)}\nADMIN_USERNAMES=admin\nAPP_HOST=0.0.0.0\nAPP_PORT=5000\nSESSION_COOKIE_SECURE=0\n")
        print(f"[+] created {env} with a new SECRET_KEY (mode 600)")
    else:
        print(f"[=] {env} exists - left untouched")

    from config import Config
    from scripts.backup_instance import backup
    from services.keys import MASTER_NAME, KeyManager

    inst = Path(Config.INSTANCE_DIR)
    inst.mkdir(parents=True, exist_ok=True)
    dbfile, kdir = inst / "cns_lab.db", inst / "keys"
    if dbfile.exists() or (kdir / MASTER_NAME).exists():
        print("[+] existing data found; backup written to", backup(inst))

    users_in_db = 0
    if dbfile.exists():
        try:
            users_in_db = sqlite3.connect(dbfile).execute("SELECT COUNT(*) FROM users").fetchone()[0]
        except sqlite3.Error:
            pass
    if os.environ.get("CNS_MASTER_KEY", "").strip():
        # Hosted database-backed mode keeps the master key in the environment
        # and never generates a competing local key during build/startup.
        KeyManager(kdir, auto_init=False)
        print("[=] CNS_MASTER_KEY configured; using persistent database-backed signing keys")
    elif (kdir / MASTER_NAME).exists():
        print("[=] master key exists - kept (never regenerated)")
    elif users_in_db:
        print(f"[!] database has {users_in_db} users but master key is missing. Refusing to create a new one.\n"
              "    Restore instance/keys from backup. Nothing was changed.")
        sys.exit(2)
    else:
        print("[+] created master key", KeyManager.initialize(kdir))

    from sqlalchemy import inspect
    from app import create_app
    from extensions import db
    app = create_app()
    with app.app_context():
        insp = inspect(db.engine)
        for name, table in db.metadata.tables.items():
            if insp.has_table(name):
                have = {c["name"] for c in insp.get_columns(name)}
                missing = set(table.c.keys()) - have
                if missing:
                    print(f"[!] existing table '{name}' lacks columns {sorted(missing)} (old schema).\n"
                          f"    Move {inst} aside (do not delete) and re-run. Nothing was changed.")
                    sys.exit(3)
        db.create_all()
        print("[+] database ready at", dbfile)
    print("[OK] initialisation complete. Start with: python3 app.py")


if __name__ == "__main__":
    main()
