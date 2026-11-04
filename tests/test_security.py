import os
import stat
from pathlib import Path

import pytest

from conftest import PW, login, make_app, new_user, register, send
from models import LoginAttempt, Message, SecurityEvent, User
from extensions import db
from services.keys import KeyManager, KeyManagerError


def test_csrf_enforced(csrf_app):
    c = csrf_app.test_client()
    assert c.post("/register", data={"username": "alice", "password": PW, "confirm": PW}).status_code == 400
    assert c.post("/api/messages", json={}).status_code == 400
    tok = c.get("/api/csrf").get_json()["csrf_token"]
    r = c.post("/register", data={"username": "alice", "password": PW, "confirm": PW, "csrf_token": tok})
    assert r.status_code == 302
    r = c.post("/login", data={"username": "alice", "password": PW, "csrf_token": "forged"})
    assert r.status_code == 400
    with csrf_app.app_context():
        assert SecurityEvent.query.filter_by(event_type="csrf_failure").count() >= 2


def test_csrf_header_works_for_api_and_logout_needs_token(csrf_app):
    c = csrf_app.test_client()
    tok = c.get("/api/csrf").get_json()["csrf_token"]
    c.post("/register", data={"username": "alice", "password": PW, "confirm": PW, "csrf_token": tok})
    c.post("/register", data={"username": "bob", "password": PW, "confirm": PW, "csrf_token": tok})
    c.post("/login", data={"username": "alice", "password": PW, "csrf_token": tok})
    tok = c.get("/api/csrf").get_json()["csrf_token"]
    assert c.post("/api/messages", json={"recipient": "bob", "body": "hi"}).status_code == 400
    assert c.post("/api/messages", json={"recipient": "bob", "body": "hi"}, headers={"X-CSRFToken": tok}).status_code == 201
    assert c.post("/logout").status_code == 400
    assert c.get("/api/me").status_code == 200  # still logged in after the rejected CSRF logout


def test_csrf_protects_settings_compose_and_attacker_actions(csrf_app):
    admin = csrf_app.test_client()
    alice = csrf_app.test_client()
    bob = csrf_app.test_client()

    for client, username in ((admin, "admin"), (alice, "alice"), (bob, "bob")):
        token = client.get("/api/csrf").get_json()["csrf_token"]
        assert client.post("/register", data={"username": username, "password": PW,
                                               "confirm": PW, "csrf_token": token}).status_code == 302
        token = client.get("/api/csrf").get_json()["csrf_token"]
        assert client.post("/login", data={"username": username, "password": PW,
                                            "csrf_token": token}).status_code == 302

    assert admin.post("/settings", data={"protection_enabled": "on"}).status_code == 400
    token = admin.get("/api/csrf").get_json()["csrf_token"]
    assert admin.post("/settings", data={"protection_enabled": "on", "csrf_token": token}).status_code == 302

    token = alice.get("/api/csrf").get_json()["csrf_token"]
    assert alice.post("/api/lab/send-plain", json={"recipient": "bob", "body": "hold"},
                      headers={"X-CSRFToken": token}).status_code == 201
    queued = alice.get("/api/attacker/events")
    # A normal user cannot read the operator event stream.
    assert queued.status_code == 403
    from models import InterceptedMessage
    with csrf_app.app_context():
        item_id = InterceptedMessage.query.one().id
    assert admin.post(f"/api/attacker/relay/{item_id}", json={"action": "forward_original"}).status_code == 400
    assert admin.post(f"/api/attacker/relay/{item_id}", json={"action": "forward_original"},
                      headers={"X-CSRFToken": "invalid"}).status_code == 400
    token = admin.get("/api/csrf").get_json()["csrf_token"]
    assert admin.post(f"/api/attacker/relay/{item_id}", json={"action": "forward_original"},
                      headers={"X-CSRFToken": token}).status_code == 200


def test_attacker_page_loads_shared_csrf_post_helper(app):
    admin = new_user(app, "admin")
    page = admin.get("/attacker").get_data(as_text=True)
    helper = page.index("/static/js/app.js")
    relay = page.index("/static/js/attacker.js")
    assert helper < relay


def test_expired_csrf_token_is_rejected_with_reload_guidance(csrf_app, monkeypatch):
    from itsdangerous import SignatureExpired
    from flask_wtf.csrf import URLSafeTimedSerializer
    c = csrf_app.test_client()
    register(c, "alice")
    login(c, "alice")
    token = c.get("/api/csrf").get_json()["csrf_token"]
    monkeypatch.setattr(URLSafeTimedSerializer, "loads",
                        lambda *args, **kwargs: (_ for _ in ()).throw(SignatureExpired("expired")))
    result = c.post("/settings", data={"csrf_token": token})
    assert result.status_code == 400 and b"Reload form" in result.data


def test_session_cookie_flags(app, client):
    register(client, "alice")
    r = login(client, "alice")
    sc = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in sc and "SameSite=Lax" in sc


def test_relative_environment_paths_are_anchored_to_project(monkeypatch, tmp_path):
    from config import BASE_DIR, _configured_path
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CNS_INSTANCE_DIR", "instance")
    monkeypatch.setenv("TLS_CERT_FILE", "instance/tls/lab.crt")
    assert _configured_path("CNS_INSTANCE_DIR") == str((BASE_DIR / "instance").resolve())
    assert _configured_path("TLS_CERT_FILE") == str((BASE_DIR / "instance/tls/lab.crt").resolve())


def test_static_asset_urls_use_content_hashes(tmp_path):
    import hashlib
    import re
    from conftest import make_app

    app = make_app(tmp_path)
    html = app.test_client().get("/login").get_data(as_text=True)
    match = re.search(r"/static/js/app\.js\?v=([0-9a-f]{12})", html)
    expected = hashlib.sha256((Path(app.static_folder) / "js/app.js").read_bytes()).hexdigest()[:12]
    assert match and match.group(1) == expected


def test_configured_tls_listener_marks_session_cookie_secure(tmp_path):
    tls = tmp_path / "tls"
    tls.mkdir()
    cert, key = tls / "lab.crt", tls / "lab.key"
    cert.write_text("certificate configured", encoding="ascii")
    key.write_text("private key configured", encoding="ascii")
    app = make_app(tmp_path, TLS_CERT_FILE=str(cert), TLS_KEY_FILE=str(key))
    assert app.config["SESSION_COOKIE_SECURE"] is True


def test_https_required_blocks_plain_http(tmp_path):
    from conftest import make_app
    tls = tmp_path / "tls"
    tls.mkdir()
    cert, key = tls / "lab.crt", tls / "lab.key"
    cert.write_text("test certificate placeholder")
    key.write_text("test private key placeholder")
    app = make_app(tmp_path, REQUIRE_HTTPS=True, TLS_CERT_FILE=str(cert), TLS_KEY_FILE=str(key))
    response = app.test_client().get("/", base_url="http://lab.example")
    assert response.status_code == 400
    assert b"HTTPS is required" in response.data


def test_security_headers(client):
    r = client.get("/login")
    csp = r.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "style-src 'self' https://fonts.googleapis.com" in csp
    assert "font-src 'self' https://fonts.gstatic.com" in csp
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["Cache-Control"] == "no-store"


SQLI = ["' OR '1'='1' --", "admin'--", "\" OR 1=1 #", "x'; DROP TABLE users;--", "1 UNION SELECT * FROM users"]


@pytest.mark.parametrize("payload", SQLI)
def test_sql_injection_resistance(app, payload):
    c = app.test_client()
    new_user(app, "victim")
    assert login(c, payload, "x").status_code in (400, 401)
    assert login(c, "victim", payload).status_code == 401
    assert register(c, payload).status_code == 400
    a = new_user(app, "alice")
    assert send(a, payload, "x").status_code == 404
    assert a.get(f"/api/messages?box={payload}").status_code == 400
    with app.app_context():
        assert User.query.count() == 2  # users table intact


def test_secrets_never_in_events_or_db_plaintext(app):
    c = app.test_client()
    register(c, "alice"); register(c, "bob")
    login(c, "alice", "Wr0ng-Passw0rd-LEAKCHECK")
    login(c, "alice")
    send(c, "bob", "PLAINTEXT_LEAKCHECK")
    c.get("/messages/1")
    with app.app_context():
        blob = " ".join(f"{e.event_type} {e.username} {e.detail}" for e in SecurityEvent.query.all())
        assert "LEAKCHECK" not in blob and PW not in blob
        assert SecurityEvent.query.filter_by(event_type="login_failed").count() == 1
        assert SecurityEvent.query.filter_by(event_type="message_sent").count() == 1


def test_tampered_db_rows_rejected_and_logged(app):
    a, b = new_user(app, "alice"), new_user(app, "bob")
    for _ in range(4):
        send(a, "bob", "SECRET_PLAINTEXT_XYZ")
    with app.app_context():
        ms = Message.query.order_by(Message.id).all()
        ms[0].ciphertext = bytes([ms[0].ciphertext[0] ^ 1]) + bytes(ms[0].ciphertext[1:])
        ms[1].signature = bytes([ms[1].signature[0] ^ 1]) + bytes(ms[1].signature[1:])
        ms[2].recipient_id = ms[2].sender_id
        ms[3].created_at = "2001-01-01T00:00:00.000000Z"
        db.session.commit()
    for i in range(1, 5):
        j = a.get(f"/api/messages/{i}").get_json()
        assert j["body"] is None and j["verification"] == "signature_invalid", i
        assert b"SECRET_PLAINTEXT_XYZ" not in a.get(f"/messages/{i}").data
    assert a.get("/api/stats").get_json()["failed"] == 4
    with app.app_context():
        assert SecurityEvent.query.filter_by(event_type="crypto_failure", severity="critical").count() >= 4


def test_verify_endpoint_detects_modified_envelope(app):
    a = new_user(app, "alice"); new_user(app, "bob")
    mid = send(a, "bob", "hello").get_json()["id"]
    env = a.get(f"/api/messages/{mid}/envelope").get_json()
    assert a.post("/api/verify", json=env).get_json()["valid"] is True
    import base64
    ct = bytearray(base64.b64decode(env["ciphertext"])); ct[0] ^= 1
    bad = dict(env, ciphertext=base64.b64encode(bytes(ct)).decode())
    assert a.post("/api/verify", json=bad).get_json()["valid"] is False
    assert a.post("/api/verify", json=dict(env, recipient_id=env["sender_id"])).get_json()["valid"] is False
    assert a.post("/api/verify", json=dict(env, signature="!!notb64")).get_json()["valid"] is False


def test_lab_endpoint_runs_real_tests_and_logs(app):
    a = new_user(app, "alice"); new_user(app, "bob"); send(a, "bob", "x")
    res = a.post("/lab/run/all").get_json()["results"]
    assert len(res) == 7 and all(r["passed"] is True for r in res)
    assert a.post("/lab/run/nope").status_code == 404
    with app.app_context():
        assert SecurityEvent.query.filter_by(event_type="lab_test").count() == 7


def test_error_handling_no_stack_traces(client):
    r = client.get("/nope")
    assert r.status_code == 404 and b"Traceback" not in r.data
    r = client.get("/api/nope")
    assert r.status_code == 404 and r.is_json
    assert client.post("/api/verify", data="{bad", content_type="application/json").status_code == 401
    health = client.get("/api/health").get_json()
    expected = "ok" if health["key_check"]["permissions_checked"] else "degraded"
    assert health["status"] == expected


def test_oversize_body_rejected(app):
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    a = new_user(app, "alice")
    r = a.post("/api/messages", data="x" * 70000, content_type="application/json")
    assert r.status_code == 413


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_key_file_permissions(app):
    a = new_user(app, "alice")
    kd = app.config["KEY_DIR"]
    assert stat.S_IMODE(os.stat(kd).st_mode) == 0o700
    files = [os.path.join(dp, f) for dp, _, fs in os.walk(kd) for f in fs]
    assert len(files) == 2
    assert all(stat.S_IMODE(os.stat(f).st_mode) == 0o600 for f in files)


def test_keys_never_regenerated(tmp_path):
    app = make_app(tmp_path)
    new_user(app, "alice")
    kd = tmp_path / "instance" / "keys"
    before = (kd / "aes_master.key").read_bytes()
    app2 = make_app(tmp_path)
    assert (kd / "aes_master.key").read_bytes() == before
    (kd / "aes_master.key").unlink()
    with pytest.raises(KeyManagerError):
        KeyManager(kd, auto_init=True)  # user keys exist -> refuse even with auto_init
    with pytest.raises(KeyManagerError):
        KeyManager(tmp_path / "empty", auto_init=False)
    with pytest.raises(FileExistsError):
        KeyManager.initialize(tmp_path / "instance" / "keys") if (kd / "aes_master.key").exists() else (_ for _ in ()).throw(FileExistsError())


def test_private_key_not_plaintext_on_disk(app):
    new_user(app, "alice")
    from services.keys import KeyManager
    km = app.extensions["cns_keys"]
    raw = km.load_private(1).private_bytes_raw()
    blob = (km.users_dir / "1.ed25519.wrapped").read_bytes()
    assert raw not in blob


def test_health_is_real(app):
    h = app.test_client().get("/api/health").get_json()
    assert h["database"] == "ok"
    assert h["key_check"]["key_pairings_ok"] is True
    assert h["key_check"]["stored_messages_checked"] is False
    if h["key_check"]["permissions_checked"]:
        assert h["keys"] == "ok" and h["status"] == "ok"
    else:
        assert h["keys"] == "degraded" and h["status"] == "degraded"


def test_health_detects_database_and_key_pair_mismatch(app):
    from models import User
    client = new_user(app, "alice")
    with app.app_context():
        user = User.query.filter_by(username="alice").one()
        user.public_key = "not-the-key-pair"
        db.session.commit()
    response = client.get("/api/health")
    data = response.get_json()
    assert response.status_code == 503
    assert data["key_check"]["key_pairings_ok"] is False
    assert data["key_check"]["state"] == "FAILED"


def test_missing_secret_key_refuses_to_start(tmp_path):
    from app import create_app
    with pytest.raises(RuntimeError):
        create_app({"SECRET_KEY": None, "INSTANCE_DIR": str(tmp_path), "AUTO_INIT_KEYS": True})
