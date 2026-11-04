"""Central configuration. Secrets come from the environment / .env only."""
import os
from datetime import timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def load_dotenv(path=None):
    p = Path(path) if path else BASE_DIR / ".env"
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


load_dotenv()


def _bool(name, default=False):
    return os.environ.get(name, "1" if default else "0").strip().lower() in ("1", "true", "yes")


def _configured_path(name, default=None):
    value = os.environ.get(name) or default
    if not value:
        return None
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = BASE_DIR / path
    return str(path.resolve())


def _database_url():
    """Read a provider URL and select the supported PostgreSQL driver."""
    value = os.environ.get("DATABASE_URL", "").strip()
    if value.startswith("postgres://"):
        value = "postgresql://" + value[len("postgres://"):]
    if value.startswith("postgresql://"):
        value = "postgresql+psycopg://" + value[len("postgresql://"):]
    return value or None


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")
    # Relative paths in .env are anchored to this application, not the shell's
    # current directory. Starting app.py from another directory must not create
    # or select a second, empty instance/database.
    INSTANCE_DIR = _configured_path("CNS_INSTANCE_DIR", BASE_DIR / "instance")
    # SQLALCHEMY_DATABASE_URI and KEY_DIR are derived from INSTANCE_DIR in create_app()
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE")
    REQUIRE_HTTPS = _bool("REQUIRE_HTTPS")
    # Enable only when the app binds to loopback behind a trusted TLS proxy.
    TRUST_PROXY = _bool("TRUST_PROXY")
    TLS_CERT_FILE = _configured_path("TLS_CERT_FILE")
    TLS_KEY_FILE = _configured_path("TLS_KEY_FILE")
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    WTF_CSRF_TIME_LIMIT = 3600

    ADMIN_USERNAMES = [u.strip().lower() for u in os.environ.get("ADMIN_USERNAMES", "admin").split(",") if u.strip()]
    APP_HOST = os.environ.get("APP_HOST", "0.0.0.0")
    APP_PORT = int(os.environ.get("APP_PORT", "5000"))

    AUTO_INIT_KEYS = False  # only tests set this; production never auto-creates keys

    LOGIN_WINDOW_SECONDS = 300
    LOGIN_MAX_FAILS_USER_IP = 5
    LOGIN_MAX_FAILS_IP = 30
    SEND_WINDOW_SECONDS = 60
    SEND_MAX_PER_WINDOW = 30
    MAX_MESSAGE_CHARS = 2000
    MAX_SCAN_BYTES = int(os.environ.get("MAX_SCAN_BYTES", str(10 * 1024 * 1024)))
    CLAMSCAN_PATH = os.environ.get("CLAMSCAN_PATH", "clamscan")
    # If clamav-daemon is installed and running, clamdscan reuses its loaded
    # signature database instead of loading signatures for every upload.
    CLAMDSCAN_PATH = os.environ.get("CLAMDSCAN_PATH", "clamdscan")
    # A cold clamscan process loads the signature database for each request;
    # allow slower VirtualBox/shared-folder hosts enough time without unbounded scans.
    CLAMSCAN_TIMEOUT = int(os.environ.get("CLAMSCAN_TIMEOUT", "120"))
    SECURITY_SCAN_TIMEOUT_SECONDS = int(os.environ.get("SECURITY_SCAN_TIMEOUT_SECONDS", "30"))
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", str(12 * 1024 * 1024)))
