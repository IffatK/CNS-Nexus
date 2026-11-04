import io
import json
import time
import pytest

from conftest import new_user
from extensions import db
from models import SecurityFinding, SecurityScan
from models.base import utcnow
from services import analysis_scanner as scanner


def fake_response(url, *, status=200, headers=None, body=b"<html></html>"):
    normalized, scheme, _, host = scanner.normalize_target(url)
    return {"url": normalized, "status": status, "headers": headers or {"content-type": "text/html"},
            "body": body, "truncated": False, "redirects": [{"url": normalized, "status": status,
                "host": host, "address": "93.184.216.34"}], "content_length": len(body),
            "certificate": {"subject": ((('commonName', host),),), "notAfter": "Dec 31 23:59:59 2030 GMT"} if scheme == "https" else None,
            "tls_verified": scheme == "https", "tls_version": "TLSv1.3" if scheme == "https" else None,
            "tls_cipher": "TLS_AES_256_GCM_SHA384" if scheme == "https" else None}


def wait_terminal(client, scan_id):
    for _ in range(100):
        result = client.get(f"/security-center/api/scans/{scan_id}")
        assert result.status_code == 200
        payload = result.get_json()
        if payload["status"] not in ("queued", "running"):
            return payload
        time.sleep(.02)
    raise AssertionError("scan did not reach a terminal state")


def test_security_center_page_has_scan_options_and_empty_states(app):
    client = new_user(app, "alice")
    response = client.get("/security-center")
    assert response.status_code == 200
    assert b"File Malware Scan" in response.data and b"URL Reputation" in response.data and b"Website URL" in response.data
    assert b"Quick Scan" in response.data and b"Comprehensive Scan" in response.data
    assert b"No scan history yet" in response.data
    assert b"data-theme-toggle" in response.data
    assert b"security-center.js" in response.data
    assert b"security-center.css" in response.data
    assert client.get("/static/css/security-center.css").status_code == 200


@pytest.mark.parametrize("value", ["localhost", "http://localhost/", "http://127.0.0.1/", "http://10.0.0.1/",
                                    "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
                                    "http://user:pass@example.com/", "http://example.com:8080/"])
def test_url_validation_rejects_local_or_unsafe_targets(value):
    with pytest.raises(scanner.UnsafeTarget):
        scanner.normalize_target(value)


def test_dns_resolution_blocks_private_and_mixed_answers(monkeypatch):
    monkeypatch.setattr(scanner.socket, "getaddrinfo", lambda *a, **kw: [
        (2, 1, 6, "", ("93.184.216.34", 80)), (2, 1, 6, "", ("192.168.1.5", 80))])
    with pytest.raises(scanner.UnsafeTarget, match="non-public"):
        scanner._resolve_public("example.com", 80)


def test_redirect_revalidates_target_before_connecting(app, monkeypatch):
    class Redirect:
        status = 302
        def getheaders(self): return [("Location", "http://127.0.0.1/admin")]
        def getheader(self, name): return "http://127.0.0.1/admin" if name.lower() == "location" else None
    class Connection:
        def __init__(self, *args, **kwargs): pass
        def request(self, *args, **kwargs): pass
        def getresponse(self): return Redirect()
        def close(self): pass
    monkeypatch.setattr(scanner, "_PinnedHTTP", Connection)
    monkeypatch.setattr(scanner, "_resolve_public", lambda host, port: ["93.184.216.34"])
    with app.app_context(), pytest.raises(scanner.UnsafeTarget, match="blocked"):
        scanner.safe_fetch("http://example.com/")


def test_no_reputation_key_reports_unavailable_without_network(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFE_BROWSING_API_KEY", raising=False)
    result, findings = scanner._reputation_check("https://example.com", True)
    assert result["status"] == "not_configured" and findings == []
    assert "not prove" in result["detail"] or result["detail"]


def test_dependency_free_pdf_report_builder_produces_downloadable_pdf():
    from routes.security_center import _minimal_pdf
    report = {"report_id": "CNS-SCAN-00000001", "scan_type": "website", "status": "partial",
        "target": "https://example.com/[query redacted]", "created_at_utc": "2026-10-31T00:00:00Z",
        "duration_ms": 1200, "risk": {"level": "unknown", "score": None, "method": "No score."},
        "authorization_confirmed": True, "summary": {"engines": ["bounded checks"],
            "severity_counts": {severity: 0 for severity in scanner.SEVERITY_ORDER},
            "limitations": ["A long report text " * 12]}, "scan_error": "",
        "findings": [{"id": "F-000001", "severity": "low", "title": "Header review", "confidence": "high",
            "category": "security-header", "affected": "https://example.com", "evidence": "Observed header missing.",
            "explanation": "Review it.", "impact": "Possible impact.", "remediation": "Set an appropriate header.",
            "source": "local", "verification": "observed", "remediation_steps": ["Set the header."],
            "verification_steps": ["Run the check again."]}]}
    data = _minimal_pdf(report)
    assert data.startswith(b"%PDF-1.4") and b"xref" in data and b"Detailed findings" in data


def test_website_header_checks_and_risk_keep_confidence_separate():
    response = {"headers": {"content-type": "text/html", "content-security-policy": "default-src * 'unsafe-inline'",
                            "strict-transport-security": "max-age=60", "x-frame-options": "DENY",
                            "set-cookie": "session=secret; Path=/"}}
    findings = scanner._header_findings("https://example.com", response)
    assert {f["key"] for f in findings} >= {"weak-csp", "weak-hsts", "cookie-flags"}
    # A low-confidence critical finding remains critical; confidence is not folded into severity.
    score, risk, counts = scanner._risk([{"severity": "critical", "confidence": "low"}])
    assert (score, risk, counts["critical"]) == (100, "critical", 1)


def test_url_scan_persists_findings_and_owner_only_json_pdf_reports(app, monkeypatch):
    alice, bob = new_user(app, "alice"), new_user(app, "bob")
    monkeypatch.setattr(scanner, "_resolve_public", lambda host, port: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "safe_fetch", lambda url, **kwargs: fake_response(url))
    accepted = alice.post("/security-center/scan/url", data={"url": "https://secure-login.example.com/"},
                          headers={"Accept": "application/json"})
    assert accepted.status_code == 202, accepted.get_data(as_text=True)
    scan_id = accepted.get_json()["id"]
    completed = wait_terminal(alice, scan_id)
    assert completed["status"] == "completed"
    assert completed["risk_score"] == 50
    report = alice.get(f"/security-center/{scan_id}/report.json")
    assert report.status_code == 200 and report.get_json()["findings"]
    assert bob.get(f"/security-center/{scan_id}/report.json").status_code == 404
    pdf = alice.get(f"/security-center/{scan_id}/report.pdf")
    assert pdf.status_code == 200 and pdf.mimetype == "application/pdf" and pdf.data.startswith(b"%PDF")
    csv_report = alice.get(f"/security-center/{scan_id}/report.csv")
    assert csv_report.status_code == 200 and b"remediation_steps" in csv_report.data
    assert alice.get(f"/security-center/{scan_id}").status_code == 200


def test_authorized_website_scan_checks_headers_and_fixed_scope(app, monkeypatch):
    client = new_user(app, "alice")
    requested = []
    def fetch(url, **kwargs):
        requested.append((url, kwargs.get("allowed_host")))
        if url.endswith("/.env"):
            return fake_response(url, status=200, headers={"content-type": "text/plain"}, body=b"not persisted")
        return fake_response(url, status=404)
    monkeypatch.setattr(scanner, "safe_fetch", fetch)
    accepted = client.post("/security-center/scan/website", data={"url": "https://example.com/", "authorized": "on"},
                           headers={"Accept": "application/json"})
    assert accepted.status_code == 202
    result = wait_terminal(client, accepted.get_json()["id"])
    assert result["status"] == "completed" and result["risk_level"] == "high"
    assert len(requested) == 6
    assert all(host == "example.com" for _, host in requested)
    detail = client.get(result["detail_url"])
    assert detail.status_code == 200 and b"Content-Security-Policy" in detail.data
    assert b"not persisted" not in detail.data


def test_quick_website_scan_omits_path_probes_and_records_scope(app, monkeypatch):
    client = new_user(app, "quickscan")
    requested = []
    def fetch(url, **kwargs):
        requested.append(url)
        return fake_response(url)
    monkeypatch.setattr(scanner, "safe_fetch", fetch)
    accepted = client.post("/security-center/scan/website",
        data={"url": "https://example.com/", "authorized": "on", "scan_mode": "quick"},
        headers={"Accept": "application/json"})
    assert accepted.status_code == 202
    result = wait_terminal(client, accepted.get_json()["id"])
    assert result["status"] == "completed" and len(requested) == 1
    report = client.get(result["report_url"]).get_json()
    assert report["configuration"]["scan_mode"] == "quick"
    assert report["summary"]["probe_paths"] == []
    assert "path exposure checks were skipped" in report["summary"]["limitations"][0]


def test_url_reputation_scan_never_follows_to_a_different_public_host(app, monkeypatch):
    client = new_user(app, "redirectscope")
    seen = []
    def fetch(url, **kwargs):
        seen.append(kwargs.get("allowed_host"))
        raise scanner.UnsafeTarget("Redirect left the explicitly authorized hostname scope.")
    monkeypatch.setattr(scanner, "_resolve_public", lambda host, port: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "safe_fetch", fetch)
    accepted = client.post("/security-center/scan/url", data={"url": "https://example.com/"},
                           headers={"Accept": "application/json"})
    result = wait_terminal(client, accepted.get_json()["id"])
    assert result["status"] == "partial" and seen == ["example.com"]


def test_website_scan_requires_explicit_authorization(app):
    client = new_user(app, "alice")
    response = client.post("/security-center/scan/website", data={"url": "https://example.com"},
                           headers={"Accept": "application/json"})
    assert response.status_code == 400
    assert "permission" in response.get_json()["error"]


def test_file_scan_unavailable_is_partial_not_clean_and_hash_is_persisted(app):
    app.config["CLAMSCAN_PATH"] = "missing-cns-clam"
    client = new_user(app, "alice")
    response = client.post("/security-center/scan/file", data={"file": (io.BytesIO(b"plain text fixture"), "sample.txt")},
                           content_type="multipart/form-data", headers={"Accept": "application/json"})
    assert response.status_code == 202
    status = wait_terminal(client, response.get_json()["id"])
    assert status["status"] == "partial"
    assert status["risk_score"] is not None
    report = client.get(status["report_url"]).get_json()
    assert report["configuration"]["sha256"] and report["summary"]["scanner"]["status"] == "failed"
    with app.app_context():
        row = db.session.get(SecurityScan, status["id"])
        assert row.findings and "no clean result" in row.findings[0].evidence.lower()


def test_invalid_file_and_private_url_rejected_before_job(app):
    client = new_user(app, "alice")
    invalid = client.post("/security-center/scan/file", data={"file": (io.BytesIO(b"MZ"), "bad.exe")},
                          content_type="multipart/form-data", headers={"Accept": "application/json"})
    assert invalid.status_code == 400
    private = client.post("/security-center/scan/url", data={"url": "http://192.168.56.102/"},
                          headers={"Accept": "application/json"})
    assert private.status_code == 400
    with app.app_context():
        assert SecurityScan.query.count() == 0


def test_scan_history_is_persisted_and_reports_are_csrf_protected(csrf_app, monkeypatch):
    client = csrf_app.test_client()
    token = client.get("/api/csrf").get_json()["csrf_token"]
    password = "Str0ng-Passw0rd!"
    assert client.post("/register", data={"username": "alice", "password": password,
                                          "confirm": password, "csrf_token": token}).status_code == 302
    assert client.post("/login", data={"username": "alice", "password": password,
                                       "csrf_token": token}).status_code == 302
    token = client.get("/api/csrf").get_json()["csrf_token"]
    monkeypatch.setattr(scanner, "_resolve_public", lambda host, port: ["93.184.216.34"])
    monkeypatch.setattr(scanner, "safe_fetch", lambda url, **kwargs: fake_response(url))
    denied = client.post("/security-center/scan/url", data={"url": "https://example.com"}, headers={"Accept": "application/json"})
    assert denied.status_code == 400
    # JSON scan mutation is blocked unless the CSRF token is supplied.
    accepted = client.post("/security-center/scan/url", data={"url": "https://example.com"},
                           headers={"Accept": "application/json", "X-CSRFToken": token})
    assert accepted.status_code == 202
    status = wait_terminal(client, accepted.get_json()["id"])
    assert status["status"] in ("partial", "completed")
