from conftest import new_user, send
from extensions import db
from models import Message, SecurityEvent


def test_send_inbox_sent_read(app):
    a, b = new_user(app, "alice"), new_user(app, "bob")
    r = send(a, "bob", "Top secret SECRET_PLAINTEXT_XYZ")
    assert r.status_code == 201
    mid = r.get_json()["id"]
    assert [m["id"] for m in b.get("/api/messages?box=inbox").get_json()["messages"]] == [mid]
    assert [m["id"] for m in a.get("/api/messages?box=sent").get_json()["messages"]] == [mid]
    assert b.get("/api/messages?box=sent").get_json()["messages"] == []
    d = b.get(f"/api/messages/{mid}").get_json()
    assert d["body"] == "Top secret SECRET_PLAINTEXT_XYZ" and d["verification"] == "verified"
    assert a.get(f"/api/messages/{mid}").get_json()["body"] == "Top secret SECRET_PLAINTEXT_XYZ"
    page = b.get(f"/messages/{mid}")
    assert page.status_code == 200 and b"Top secret SECRET_PLAINTEXT_XYZ" in page.data


def test_form_compose_flow(app):
    a, b = new_user(app, "alice"), new_user(app, "bob")

    r = a.post(
        "/compose",
        data={
            "recipient": "bob",
            "body": "<script>alert(1)</script>",
        },
    )

    assert r.status_code == 302

    # The compose form enters the attacker relay queue;
    # it is not delivered directly to Bob.
    from models import InterceptedMessage

    with app.app_context():
        queued = InterceptedMessage.query.filter_by(
            sender_username="alice",
            recipient_username="bob",
        ).first()

        assert queued is not None
        assert queued.status == "pending"
        assert "<script>alert(1)</script>" in queued.original_body

    # The lab relay forwards the unchanged original only after an explicit action.
    inbox = b.get("/api/messages?box=inbox").get_json()
    assert inbox["messages"] == []
    operator = app.test_client()
    from conftest import login, register
    register(operator, "admin")
    login(operator, "admin")
    delivered = operator.post(
        f"/api/attacker/relay/{queued.id}",
        json={"action": "forward_original"},
    )
    assert delivered.status_code == 200
    page = b.get(f"/messages/{delivered.get_json()['message_id']}")
    assert page.status_code == 200
    assert b"<script>alert(1)</script>" not in page.data
    assert b"&lt;script&gt;alert(1)&lt;/script&gt;" in page.data


def test_compose_recipient_is_registered_user_dropdown(app):
    alice, bob = new_user(app, "alice"), new_user(app, "bob")
    response = alice.get("/compose")
    assert response.status_code == 200
    assert b'<select id="recipient" name="recipient"' in response.data
    assert b'value="bob"' in response.data and b">bob</option>" in response.data
    assert b'value="alice"' not in response.data


def test_ciphertext_stored_not_plaintext(app):
    a = new_user(app, "alice"); new_user(app, "bob")
    send(a, "bob", "SECRET_PLAINTEXT_XYZ")
    with app.app_context():
        m = Message.query.one()
        assert b"SECRET_PLAINTEXT_XYZ" not in bytes(m.ciphertext)
        assert len(m.nonce) == 12 and len(m.signature) == 64


def test_validation_and_unknown_recipient(app):
    a = new_user(app, "alice"); new_user(app, "bob")
    assert send(a, "bob", "").status_code == 400
    assert send(a, "bob", "   ").status_code == 400
    assert send(a, "bob", "x" * 2001).status_code == 400
    assert send(a, "nobody", "hi").status_code == 404
    assert a.post("/api/messages", json={"recipient": ["bob"], "body": 5}).status_code == 400
    assert a.post("/api/messages", data="notjson", content_type="application/json").status_code == 400


def test_messages_persist_across_app_restart(tmp_path):
    from conftest import make_app
    app1 = make_app(tmp_path)
    a, _ = new_user(app1, "alice"), new_user(app1, "bob")
    send(a, "bob", "persist me")
    with app1.app_context():
        db.session.remove(); db.engine.dispose()
    app2 = make_app(tmp_path)  # same instance dir: same DB, same keys
    from conftest import login
    b = app2.test_client(); login(b, "bob")
    assert b.get("/api/messages/1").get_json()["body"] == "persist me"


def test_send_throttle(tmp_path):
    from conftest import make_app
    app = make_app(tmp_path, SEND_MAX_PER_WINDOW=3)
    a = new_user(app, "alice"); new_user(app, "bob")
    codes = [send(a, "bob", "m").status_code for _ in range(5)]
    assert codes == [201, 201, 201, 429, 429]


def test_dashboard_empty_and_real_counts(app):
    a = new_user(app, "alice"); b = new_user(app, "bob")
    page = a.get("/dashboard").data
    assert b"No messages yet" in page
    send(a, "bob", "hi")
    s = b.get("/api/stats").get_json()
    assert s["users"] == 2 and s["inbox"] == 1 and s["sent"] == 0 and s["verified"] == 1 and s["failed"] == 0
    assert b"last 7 days" in a.get("/dashboard?days=7").data
    assert b"last 30 days" in a.get("/dashboard?days=999").data
    assert b"No messages yet" not in a.get("/dashboard").data


def test_mailbox_filters_and_pagination_metadata_only(app):
    alice, bob, _ = new_user(app, "alice"), new_user(app, "bob"), new_user(app, "carol")
    one = send(alice, "bob", "body marker should not be searchable").get_json()["id"]
    two = send(alice, "carol", "another message").get_json()["id"]
    page = bob.get("/inbox?q=alice&sender=alice&date_from=2020-01-01")
    assert page.status_code == 200 and f"/messages/{one}".encode() in page.data
    assert f"/messages/{two}".encode() not in page.data
    # Search deliberately covers metadata only, never plaintext or ciphertext contents.
    assert b"body marker should not be searchable" not in bob.get("/inbox?q=body%20marker").data
    assert b"body marker should not be searchable" in bob.get(f"/messages/{one}").data
    assert alice.get("/sent?recipient=carol").status_code == 200
    assert alice.get("/inbox?date_from=not-a-date").status_code == 400
