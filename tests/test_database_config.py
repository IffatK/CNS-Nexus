from config import _database_url


def test_database_url_defaults_to_sqlite(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert _database_url() is None


def test_supabase_postgres_url_uses_psycopg_driver(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://user:secret@db.example.test:5432/app?sslmode=require")
    assert _database_url() == "postgresql+psycopg://user:secret@db.example.test:5432/app?sslmode=require"


def test_postgresql_url_uses_psycopg_driver(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:secret@db.example.test:5432/app")
    assert _database_url() == "postgresql+psycopg://user:secret@db.example.test:5432/app"
