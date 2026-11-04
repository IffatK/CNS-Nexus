PASSWORD = "Str0ng-Passw0rd!"


def register(client, username):
    return client.post("/register", data={"username": username, "password": PASSWORD, "confirm": PASSWORD})


def login(client, username):
    return client.post("/login", data={"username": username, "password": PASSWORD})


def test_auth_page_loads_shared_persistent_theme(client):
    response = client.get("/login")
    assert response.status_code == 200
    assert b'data-theme-toggle' in response.data
    assert b'theme.js' in response.data
    assert client.get("/static/js/theme.js").status_code == 200


def test_attacker_dashboard_exposes_real_diagnostics_and_routes(app):
    client = app.test_client()
    assert register(client, "admin").status_code == 302
    assert login(client, "admin").status_code == 302

    response = client.get("/attacker")
    assert response.status_code == 200
    assert b'data-theme-toggle' in response.data
    assert b'id="diagnostics"' in response.data
    assert b'id="diagnostic-rows"' in response.data
    assert b'dashboard.events_csv' not in response.data  # Jinja resolved the working endpoint URL.
    assert b'/events.csv' in response.data
    assert b'/settings' in response.data
    assert b'id="activity-feed"' in response.data
    assert b"recorded actions only" in response.data


def test_system_diagnostics_api_returns_truthful_component_states(app):
    client = app.test_client()
    assert register(client, "admin").status_code == 302
    assert login(client, "admin").status_code == 302
    response = client.get("/api/diagnostics")
    assert response.status_code == 200
    components = response.get_json()["components"]
    assert components
    assert all(c["status"] in {"HEALTHY", "DEGRADED", "NOT CONFIGURED", "UNAVAILABLE", "FAILED"}
               for c in components)
    assert all("checked_at" in c and "detail" in c for c in components)
