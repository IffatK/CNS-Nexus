import io

from conftest import new_user
from extensions import db
from models import FileShare, MalwareScan, SharedFile


def clean_scan(*args, **kwargs):
    return {"status": "clean", "error": "", "engine": "ClamAV test", "definitions": "test",
            "detection": "", "duration_ms": 2}


def test_missing_clamav_is_scan_failed_never_clean(app):
    app.config["CLAMSCAN_PATH"] = "cns-no-such-clamscan"
    client = new_user(app, "alice")
    assert b"ClamAV" in client.get("/virus-scanner").data
    assert b"Timeout" in client.get("/files").data
    assert b"upload-progress.js" in client.get("/files").data
    assert b"spinner" in client.get("/virus-scanner").data
    result = client.post("/virus-scanner/scan", data={
        "file": (io.BytesIO(b"safe text sample"), "sample.txt")
    }, content_type="multipart/form-data")
    assert result.status_code == 302
    with app.app_context():
        scan = MalwareScan.query.one()
        assert scan.status == "failed"
        assert "unavailable" in scan.error.lower()
        assert list((app.config["INSTANCE_DIR"] and __import__("pathlib").Path(app.config["INSTANCE_DIR"]) / "scanner-tmp").glob("*")) == []


def test_clean_macro_enabled_office_file_is_marked_suspicious(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from services import scanner
    responses = iter([
        SimpleNamespace(returncode=0, stdout="ClamAV 1.4/12345/Mon", stderr=""),
        SimpleNamespace(returncode=0, stdout="sample.docm: OK", stderr=""),
    ])
    monkeypatch.setattr(scanner.subprocess, "run", lambda *args, **kwargs: next(responses))
    path = tmp_path / "uploaded.bin"
    path.write_bytes(b"mock office archive")
    result = scanner.scan_path(str(path), filename="sample.docm")
    assert result["status"] == "suspicious"
    assert "manual review" in result["error"].lower()


def test_scanner_records_clean_and_rejects_fake_file_type(app, monkeypatch):
    import routes.virus_scanner as virus_route
    monkeypatch.setattr(virus_route, "scan_path", clean_scan)
    client = new_user(app, "alice")
    bad_type = client.post("/virus-scanner/scan", data={
        "file": (io.BytesIO(b"not a PDF"), "report.pdf")
    }, content_type="multipart/form-data")
    assert bad_type.status_code == 302
    with app.app_context():
        assert MalwareScan.query.count() == 0
    clean = client.post("/virus-scanner/scan", data={
        "file": (io.BytesIO(b"ordinary text"), "notes.txt")
    }, content_type="multipart/form-data")
    assert clean.status_code == 302
    with app.app_context():
        scan = MalwareScan.query.one()
        assert scan.status == "clean" and len(scan.sha256) == 64
    assert b"CLEAN" in client.get("/virus-scanner").data
    assert client.get("/virus-scanner/reports.csv").headers["Content-Disposition"].startswith("attachment;")


def test_file_share_is_authorized_scanned_and_hash_checked(app, monkeypatch):
    import routes.files as files_route
    monkeypatch.setattr(files_route, "scan_path", clean_scan)
    owner, recipient, outsider = new_user(app, "owner"), new_user(app, "recipient"), new_user(app, "outsider")
    uploaded = owner.post("/files/upload", data={
        "file": (io.BytesIO(b"private file contents"), "notes.txt")
    }, content_type="multipart/form-data")
    assert uploaded.status_code == 302
    with app.app_context():
        file_row = SharedFile.query.one()
        file_id = file_row.id
        assert file_row.scan_status == "clean"
        assert MalwareScan.query.filter_by(status="clean").count() == 1
    assert outsider.get(f"/files/{file_id}/download").status_code == 404
    shared = owner.post(f"/files/{file_id}/share", data={"recipient": "recipient", "expires_days": "7"})
    assert shared.status_code == 302
    download = recipient.get(f"/files/{file_id}/download")
    assert download.status_code == 200 and download.data == b"private file contents"
    with app.app_context():
        row = db.session.get(SharedFile, file_id)
        ( __import__("pathlib").Path(app.config["INSTANCE_DIR"]) / "shared-files" / row.storage_key).write_bytes(b"changed")
    assert recipient.get(f"/files/{file_id}/download").status_code == 409
    with app.app_context():
        assert FileShare.query.count() == 1


def test_file_share_multiselect_accepts_only_registered_users(app, monkeypatch):
    import routes.files as files_route
    monkeypatch.setattr(files_route, "scan_path", clean_scan)
    owner, alice, bob = new_user(app, "owner"), new_user(app, "alice"), new_user(app, "bob")
    uploaded = owner.post("/files/upload", data={"file": (io.BytesIO(b"team document"), "team.txt")},
                          content_type="multipart/form-data")
    assert uploaded.status_code == 302
    with app.app_context():
        file_id = SharedFile.query.one().id
    assert b"user-multi-select" in owner.get("/files").data
    response = owner.post(f"/files/{file_id}/share", data={"recipients": ["alice", "bob"], "expires_days": "30"})
    assert response.status_code == 302
    assert alice.get(f"/files/{file_id}/download").data == b"team document"
    assert bob.get(f"/files/{file_id}/download").data == b"team document"
    with app.app_context():
        assert FileShare.query.filter_by(file_id=file_id).count() == 2


def test_client_cannot_share_file_with_admin(app, monkeypatch):
    import routes.files as files_route
    monkeypatch.setattr(files_route, "scan_path", clean_scan)
    owner = new_user(app, "owner")
    new_user(app, "admin")
    uploaded = owner.post("/files/upload", data={"file": (io.BytesIO(b"client file"), "client.txt")},
                          content_type="multipart/form-data")
    assert uploaded.status_code == 302
    with app.app_context():
        file_id = SharedFile.query.one().id
    response = owner.post(f"/files/{file_id}/share", data={"recipients": ["admin"]})
    assert response.status_code == 302
    with app.app_context():
        assert FileShare.query.filter_by(file_id=file_id).count() == 0

