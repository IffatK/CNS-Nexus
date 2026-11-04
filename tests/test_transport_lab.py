import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from extensions import db

PW = "Str0ng-Passw0rd!"

def register(client, username):
    return client.post("/register", data={"username": username, "password": PW, "confirm": PW})

def login(client, username):
    return client.post("/login", data={"username": username, "password": PW})

def _b64(data):
    return base64.b64encode(data).decode("ascii")


def operator(app):
    client = app.test_client()
    register(client, "admin")
    login(client, "admin")
    return client

def test_lab_capture_changes_when_transport_protection_is_enabled(app):
    monitor = operator(app)
    client = app.test_client()
    assert register(client, "alice").status_code == 302
    assert login(client, "alice").status_code == 302
    other = app.test_client()
    assert register(other, "bob").status_code == 302
    assert login(other, "bob").status_code == 302
    response = client.post("/api/lab/send-plain", json={"recipient": "bob", "body": "lab secret in plaintext"})
    assert response.status_code == 201
    events = monitor.get("/api/attacker/events").get_json()
    assert any(c["protection"] == "plaintext" and c["content"] == "lab secret in plaintext" for c in events["captures"])

    assert client.post("/settings", data={"protection_enabled": "on"}).status_code == 302
    refused_plain = client.post("/api/lab/send-plain", json={"recipient": "bob", "body": "protected users only"})
    assert refused_plain.status_code == 409
    pk = client.get("/api/transport/public-key").get_json()
    p, g, y = int(pk["p"], 16), int(pk["g"], 16), int(pk["y"], 16)
    aes_key, nonce = os.urandom(32), os.urandom(12)
    aad = (pk["aad"] + "|bob").encode()
    ciphertext = AESGCM(aes_key).encrypt(nonce, b"protected lab message", aad)
    m = int.from_bytes(aes_key, "big")
    k = int.from_bytes(os.urandom(192), "big") % (p - 2) + 2
    c1, c2 = pow(g, k, p), (m * pow(y, k, p)) % p
    response = client.post("/api/lab/send-protected", json={
        "recipient": "bob", "elgamal_c1": format(c1, "x"), "elgamal_c2": format(c2, "x"),
        "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)
    })
    assert response.status_code == 201, response.get_json()
    delivered = other.get(f"/api/messages/{response.get_json()['id']}").get_json()
    assert delivered["body"] == "protected lab message"
    assert delivered["verification"] == "verified"
    assert delivered["protection"] == "protected"
    events = monitor.get("/api/attacker/events").get_json()
    # Protected sender traffic is not exposed in the attacker console at all.
    assert not [c for c in events["captures"] if c["protection"] == "protected"]
    assert all(row["protection"] not in ("protected", "plaintext") or row["username"] != "alice"
               for row in events["messages"])
    assert "protected lab message" not in str(events)
    diagnostics = monitor.get("/api/attacker/diagnostics?days=7")
    assert diagnostics.status_code == 200
    assert "protected lab message" not in diagnostics.get_data(as_text=True)

def test_tamper_demo_rejects_a_modified_copy(app):
    monitor = operator(app)
    sender = app.test_client()
    recipient = app.test_client()
    register(sender, "sender")
    login(sender, "sender")
    register(recipient, "recipient")
    login(recipient, "recipient")
    response = sender.post("/api/messages", json={"recipient": "recipient", "body": "tamper me"})
    assert response.status_code == 201
    result = monitor.post("/api/attacker/tamper-demo")
    assert result.status_code == 200
    assert result.get_json()["result"] == "PASS"


def test_manual_relay_forwards_original_as_unprotected_not_verified(app):
    monitor = operator(app)
    sender = app.test_client()
    recipient = app.test_client()
    register(sender, "sender")
    login(sender, "sender")
    register(recipient, "recipient")
    login(recipient, "recipient")
    held = sender.post("/api/lab/send-plain", json={"recipient": "recipient", "body": "original payload"})
    assert held.status_code == 201
    assert recipient.get("/api/messages?box=inbox").get_json()["messages"] == []
    forwarded = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}", json={"action": "forward_original"})
    assert forwarded.status_code == 200
    delivered = recipient.get(f"/api/messages/{forwarded.get_json()['message_id']}").get_json()
    assert delivered["body"] == "original payload"
    assert delivered["verification"] == "unprotected"
    assert delivered["protection"] == "plaintext_relay"
    diagnostics = monitor.get("/api/attacker/diagnostics?days=7")
    assert diagnostics.status_code == 200
    assert any(row["id"] == delivered["id"] for row in diagnostics.get_json()["integrity"])
    from models import Message
    with app.app_context():
        from models import User
        from services.crypto import public_key_from_b64, verify_envelope
        stored = db.session.get(Message, delivered["id"])
        assert len(stored.signature) == 64
        verify_envelope(stored.to_envelope(), public_key_from_b64(db.session.get(User, stored.sender_id).public_key))
    duplicate = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}", json={"action": "forward_original"})
    assert duplicate.status_code == 409


def test_manual_relay_edit_is_visible_without_specific_notice_when_both_unprotected(app):
    monitor = operator(app)
    sender = app.test_client()
    recipient = app.test_client()
    register(sender, "sender")
    login(sender, "sender")
    register(recipient, "recipient")
    login(recipient, "recipient")
    held = sender.post("/api/lab/send-plain", json={"recipient": "recipient", "body": "before edit"})
    forwarded = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}", json={
        "action": "forward_edited", "body": "after edit"
    })
    assert forwarded.status_code == 200 and forwarded.get_json()["changed"] is True
    delivered = recipient.get(f"/api/messages/{forwarded.get_json()['message_id']}").get_json()
    assert delivered["body"] == "after edit"
    assert delivered["verification"] == "unprotected"
    assert "relay_report" not in delivered and "relay_ip" not in delivered
    assert b"Attacker relay report" not in recipient.get(f"/messages/{forwarded.get_json()['message_id']}").data
    from models import Message
    with app.app_context():
        stored = db.session.get(Message, delivered["id"])
        assert not stored.signature
        assert stored.protection == "plaintext_relay"


def test_unprotected_sender_to_protected_receiver_reports_relay_and_withholds_tampered_body(app):
    monitor = operator(app)
    sender, recipient = app.test_client(), app.test_client()
    register(sender, "sender")
    login(sender, "sender")
    register(recipient, "recipient")
    login(recipient, "recipient")
    assert recipient.post("/settings", data={"protection_enabled": "on"}).status_code == 302
    held = sender.post("/api/lab/send-plain", json={"recipient": "recipient", "body": "original private text"})
    assert held.status_code == 201
    console = monitor.get("/api/attacker/events").get_json()
    assert any(row["body"] == "original private text" for row in console["pending"])
    edited = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}", json={
        "action": "forward_edited", "body": "relay replacement text"
    })
    assert edited.status_code == 200
    message_id = edited.get_json()["message_id"]
    delivered = recipient.get(f"/api/messages/{message_id}").get_json()
    assert delivered["body"] is None and delivered["verification"] == "signature_invalid"
    assert delivered["relay_report"] is True and delivered["relay_tampered"] is True
    assert delivered["relay_ip"] == "127.0.0.1"
    page = recipient.get(f"/messages/{message_id}").get_data(as_text=True)
    assert "Attacker relay report" in page and "127.0.0.1" in page
    assert "edited content is withheld" in page and "relay replacement text" not in page


def test_manual_relay_drop_never_delivers(app):
    monitor = operator(app)
    sender = app.test_client()
    recipient = app.test_client()
    register(sender, "sender")
    login(sender, "sender")
    register(recipient, "recipient")
    login(recipient, "recipient")
    held = sender.post("/api/lab/send-plain", json={"recipient": "recipient", "body": "drop me"})
    dropped = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}", json={"action": "drop"})
    assert dropped.status_code == 200
    assert recipient.get("/api/messages?box=inbox").get_json()["messages"] == []


def test_attacker_console_requires_admin(app):
    ordinary = app.test_client()
    register(ordinary, "alice")
    login(ordinary, "alice")
    assert ordinary.get("/api/attacker/events").status_code == 403
    assert ordinary.get("/attacker").status_code == 403


def test_client_users_cannot_discover_or_message_admin_accounts(app):
    admin = operator(app)
    ordinary = app.test_client()
    assert register(ordinary, "alice").status_code == 302
    assert login(ordinary, "alice").status_code == 302

    compose = ordinary.get("/compose")
    files = ordinary.get("/files")
    assert compose.status_code == 200 and b'value="admin"' not in compose.data
    assert files.status_code == 200 and b'value="admin"' not in files.data
    assert ordinary.get("/attacker").status_code == 403

    # All message transports resolve recipients through the role-aware lookup.
    assert ordinary.post("/api/messages", json={"recipient": "admin", "body": "hello"}).status_code == 404
    assert ordinary.post("/api/lab/send-plain", json={"recipient": "admin", "body": "hello"}).status_code == 404
    assert ordinary.post("/compose", data={"recipient": "admin", "body": "hello"}).status_code == 404
    assert admin.get("/api/attacker/events").status_code == 200


def test_configured_admin_name_is_hidden_even_if_legacy_role_flag_is_false(app):
    admin = operator(app)
    with app.app_context():
        from models import User
        account = User.query.filter_by(username="admin").one()
        account.is_admin = False  # simulate a legacy/misconfigured row
        db.session.commit()

    ordinary = app.test_client()
    assert register(ordinary, "alice").status_code == 302
    assert login(ordinary, "alice").status_code == 302
    assert b'value="admin"' not in ordinary.get("/compose").data
    assert ordinary.post("/api/messages", json={"recipient": "admin", "body": "hello"}).status_code == 404


def test_client_and_attacker_routes_render_distinct_pages(app):
    from flask import template_rendered

    client = app.test_client()
    register(client, "alice")
    login(client, "alice")
    client_page = client.get("/dashboard")
    assert client_page.status_code == 200
    assert b'data-page="client"' in client_page.data
    assert b'data-page="attacker"' not in client_page.data

    admin = operator(app)
    rendered = []
    def record_template(sender, template, context, **extra):
        rendered.append(template.name)
    template_rendered.connect(record_template, app)
    try:
        attacker_page = admin.get("/attacker")
    finally:
        template_rendered.disconnect(record_template, app)
    assert attacker_page.status_code == 200
    assert b'data-page="attacker"' in attacker_page.data
    assert b'data-page="client"' not in attacker_page.data
    assert b'Manual interception queue' in attacker_page.data
    assert rendered == ["attacker.html"]

    rules = {rule.rule: rule.endpoint for rule in app.url_map.iter_rules()}
    assert rules["/"] == "index"
    assert rules["/attacker"] == "attacker.page"


def test_transport_settings_uses_authenticated_session_and_allows_unprotected_sender_to_protected_recipient(app):
    sender, recipient = app.test_client(), app.test_client()
    assert register(sender, "sender").status_code == 302 and login(sender, "sender").status_code == 302
    assert register(recipient, "recipient").status_code == 302 and login(recipient, "recipient").status_code == 302
    anonymous = app.test_client()
    assert anonymous.get("/api/transport/settings?recipient=recipient").status_code == 401
    assert sender.get("/api/transport/settings?recipient=recipient").status_code == 200
    assert sender.get("/").status_code == 302
    assert sender.get("/attacker").status_code == 403
    assert operator(app).get("/attacker").status_code == 200

    assert recipient.post("/settings", data={"protection_enabled": "on"}).status_code == 302
    mode = sender.get("/api/transport/settings?recipient=recipient").get_json()
    assert mode["policy_mismatch"] is False and mode["both_enabled"] is False
    assert mode["protection_enabled"] is False and mode["recipient_enabled"] is True
    held = sender.post("/api/lab/send-plain", json={"recipient": "recipient", "body": "visible to relay"})
    assert held.status_code == 201
    form_held = sender.post("/compose", data={"recipient": "recipient", "body": "form relay"})
    assert form_held.status_code == 302
    with app.app_context():
        from models import InterceptedMessage, SecurityEvent
        assert InterceptedMessage.query.count() == 2
        assert all(item.recipient_protected for item in InterceptedMessage.query.all())
        assert SecurityEvent.query.filter_by(event_type="plaintext_transport_blocked").count() == 0
    assert held.get_json()["id"] in [row["id"] for row in operator(app).get("/api/attacker/events").get_json()["pending"]]


def test_protection_enabled_after_interception_does_not_revoke_exposed_plaintext(app):
    monitor = operator(app)
    sender, recipient = app.test_client(), app.test_client()
    assert register(sender, "sender").status_code == 302 and login(sender, "sender").status_code == 302
    assert register(recipient, "recipient").status_code == 302 and login(recipient, "recipient").status_code == 302
    held = sender.post("/api/lab/send-plain", json={"recipient": "recipient", "body": "queued before protection"})
    assert held.status_code == 201
    assert sender.post("/settings", data={"protection_enabled": "on"}).status_code == 302
    edited = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}",
                          json={"action": "forward_edited", "body": "tampered text"})
    assert edited.status_code == 200
    delivered = recipient.get(f"/api/messages/{edited.get_json()['message_id']}").get_json()
    assert delivered["body"] == "tampered text" and delivered["verification"] == "unprotected"
    with app.app_context():
        from models import InterceptedMessage, SecurityEvent
        assert InterceptedMessage.query.one().status == "tampered"
        assert SecurityEvent.query.filter_by(event_type="attacker_action_blocked").count() == 0
    charts = monitor.get("/api/attacker/diagnostics?days=7")
    assert charts.status_code == 200
    data = charts.get_json()
    assert len(data["timeline"]) == 7
    assert sum(row["blocked"] for row in data["timeline"]) == 0
    assert data["attack_types"]["tamper"]["successful"] == 1
    assert data["outcomes"]["pending"] == 0


def test_attacker_simulation_persists_run_and_downloadable_report(app):
    monitor = operator(app)
    alice, bob = app.test_client(), app.test_client()
    assert register(alice, "alice").status_code == 302 and login(alice, "alice").status_code == 302
    assert register(bob, "bob").status_code == 302 and login(bob, "bob").status_code == 302
    sent = alice.post("/api/lab/send-plain", json={"recipient": "bob", "body": "synthetic replay fixture"})
    delivered = monitor.post(f"/api/attacker/relay/{sent.get_json()['id']}", json={"action": "forward_original"})
    assert delivered.status_code == 200
    result = monitor.post("/api/attacker/simulations/replay", json={"message_id": delivered.get_json()["message_id"]})
    assert result.status_code == 200
    payload = result.get_json()
    assert payload["outcome"] == "blocked"
    report = monitor.get(f"/api/attacker/reports/{payload['run_id']}")
    assert report.status_code == 200
    assert report.mimetype == "application/json"
    assert payload["run_id"] in report.get_data(as_text=True)
    assert "attacker_simulation_completed" in report.get_data(as_text=True)


def test_attacker_controls_reject_malformed_json_types(app):
    monitor = operator(app)
    alice, bob = app.test_client(), app.test_client()
    assert register(alice, "alice").status_code == 302 and login(alice, "alice").status_code == 302
    assert register(bob, "bob").status_code == 302 and login(bob, "bob").status_code == 302
    held = alice.post("/api/lab/send-plain", json={"recipient": "bob", "body": "validate controls"})
    bad_action = monitor.post(f"/api/attacker/relay/{held.get_json()['id']}", json={"action": []})
    assert bad_action.status_code == 400
    bad_id = monitor.post("/api/attacker/simulations/replay", json={"message_id": True})
    assert bad_id.status_code == 400


def test_attacker_simulations_use_access_control_and_drop_real_pending_item(app):
    monitor = operator(app)
    alice, bob = app.test_client(), app.test_client()
    assert register(alice, "alice").status_code == 302 and login(alice, "alice").status_code == 302
    assert register(bob, "bob").status_code == 302 and login(bob, "bob").status_code == 302
    sent = alice.post("/api/lab/send-plain", json={"recipient": "bob", "body": "access test fixture"})
    delivered = monitor.post(f"/api/attacker/relay/{sent.get_json()['id']}", json={"action": "forward_original"})
    denied = monitor.post("/api/attacker/simulations/unauthorized_access", json={"message_id": delivered.get_json()["message_id"]})
    assert denied.status_code == 200 and denied.get_json()["outcome"] == "blocked"

    inbox_before = bob.get("/api/messages?box=inbox").get_json()["messages"]
    held = alice.post("/api/lab/send-plain", json={"recipient": "bob", "body": "drop through simulation"})
    dropped = monitor.post("/api/attacker/simulations/dropping", json={"queue_id": held.get_json()["id"]})
    assert dropped.status_code == 200 and dropped.get_json()["outcome"] == "dropped"
    inbox = bob.get("/api/messages?box=inbox").get_json()["messages"]
    assert [row["id"] for row in inbox] == [row["id"] for row in inbox_before]


def test_attacker_simulation_routes_require_admin_and_csrf(csrf_app):
    pw = "Str0ng-Passw0rd!"
    def authenticate(username):
        client = csrf_app.test_client()
        csrf = client.get("/api/csrf").get_json()["csrf_token"]
        headers = {"X-CSRFToken": csrf}
        assert client.post("/register", data={"username": username, "password": pw,
                                               "confirm": pw}, headers=headers).status_code == 302
        assert client.post("/login", data={"username": username, "password": pw}, headers=headers).status_code == 302
        headers = {"X-CSRFToken": client.get("/api/csrf").get_json()["csrf_token"]}
        return client, headers
    ordinary, ordinary_headers = authenticate("alice")
    assert ordinary.post("/api/attacker/simulations/tampering", json={}, headers=ordinary_headers).status_code == 403

    admin, admin_headers = authenticate("admin")
    without_csrf = admin.post("/api/attacker/simulations/tampering", json={})
    assert without_csrf.status_code == 400
    with_csrf = admin.post("/api/attacker/simulations/tampering", json={}, headers=admin_headers)
    assert with_csrf.status_code == 200
