import hashlib
import io
import json
import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from extensions import db
from models import FileShare, MalwareScan, SecurityScan, SharedFile, User
from models.base import utcnow
from services.scanner import file_type_matches, scan_path, scanner_status
from services.security_log import log_event
from services.roles import client_users
from services.file_storage import delete_file, put_file, read_file, uses_supabase_storage

bp = Blueprint("files", __name__)
ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip", ".7z"}


def _storage_root():
    root = Path(current_app.config["INSTANCE_DIR"]) / "shared-files"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _accessible_shares():
    now = utcnow()
    query = FileShare.query.filter_by(recipient_id=current_user.id, revoked_at=None).filter(
        (FileShare.expires_at.is_(None)) | (FileShare.expires_at > now))
    if not current_user.is_admin:
        query = query.join(SharedFile, FileShare.file_id == SharedFile.id).join(
        User, SharedFile.owner_id == User.id)
        query = client_users(query)
    return query


@bp.get("/files")
@login_required
def page():
    owned = SharedFile.query.filter_by(owner_id=current_user.id).order_by(SharedFile.id.desc()).limit(100).all()
    shared = _accessible_shares().order_by(FileShare.id.desc()).limit(100).all()
    binary = current_app.config["CLAMSCAN_PATH"]
    engine_available = scanner_status(binary)["available"]
    users_query = User.query.filter(User.id != current_user.id)
    if not current_user.is_admin:
        users_query = client_users(users_query)
    users = users_query.order_by(User.username.asc()).all()
    return render_template("files.html", owned=owned, shared=shared, users=users, engine_available=engine_available,
                           virustotal_configured=bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip()),
                           supabase_storage=uses_supabase_storage(),
                           render_deploy=bool(os.environ.get("RENDER")),
                           max_mb=current_app.config["MAX_SCAN_BYTES"] // (1024 * 1024))


@bp.post("/files/upload")
@login_required
def upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        flash("Choose a file to upload.", "warning")
        return redirect(url_for("files.page"))
    filename = secure_filename(upload.filename)[:255]
    if not filename or Path(filename).suffix.lower() not in ALLOWED_EXTENSIONS:
        flash("That file type is not supported.", "warning")
        return redirect(url_for("files.page"))
    if request.form.get("upload_file_to_virustotal") == "on":
        if not os.environ.get("VIRUSTOTAL_API_KEY", "").strip():
            flash("VirusTotal is not configured. Add VIRUSTOTAL_API_KEY in the deployment environment.", "warning")
            return redirect(url_for("files.page"))
        active = SecurityScan.query.filter_by(user_id=current_user.id).filter(
            SecurityScan.status.in_(("queued", "running"))).count()
        if active >= 2:
            flash("You already have two scans queued or running. Please wait for one to finish.", "warning")
            return redirect(url_for("files.page"))
        from services.analysis_scanner import safe_scan_file, submit_scan
        try:
            temp_name, size, digest, mime = safe_scan_file(upload, filename,
                current_app.config["MAX_SCAN_BYTES"], Path(current_app.config["INSTANCE_DIR"]) / "scanner-tmp")
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("files.page"))
        if not file_type_matches(temp_name, Path(filename).suffix.lower()):
            Path(temp_name).unlink(missing_ok=True)
            flash("File contents do not match the filename type.", "warning")
            return redirect(url_for("files.page"))
        scan = SecurityScan(user_id=current_user.id, scan_type="file", target=filename, status="queued",
            config_json=json.dumps({"sha256": digest, "size_bytes": size, "mime_type": mime,
                "upload_file_to_virustotal": True, "store_shared_file_on_clean": True, "temp_path": temp_name}))
        db.session.add(scan)
        db.session.commit()
        if not submit_scan(current_app._get_current_object(), scan.id, temp_name):
            scan.status, scan.error, scan.completed_at = "failed", "Scanner queue is full; retry later.", utcnow()
            db.session.commit()
            Path(temp_name).unlink(missing_ok=True)
            flash(scan.error, "warning")
            return redirect(url_for("files.page"))
        log_event("security_scan_queued", "info", user=current_user,
                  detail=f"scan_id={scan.id} scan_type=file provider=virustotal action=private_file_storage")
        return redirect(url_for("security_center.detail", scan_id=scan.id))
    temp_dir = Path(current_app.config["INSTANCE_DIR"]) / "scanner-tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="share-scan-", suffix=".bin", dir=temp_dir)
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = upload.stream.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > current_app.config["MAX_SCAN_BYTES"]:
                    flash("File exceeds the configured upload size limit.", "warning")
                    return redirect(url_for("files.page"))
                digest.update(chunk)
                out.write(chunk)
        if not file_type_matches(temp_name, Path(filename).suffix.lower()):
            flash("File contents do not match the filename type.", "warning")
            return redirect(url_for("files.page"))
        scan = scan_path(temp_name, current_app.config["CLAMSCAN_PATH"], current_app.config["CLAMSCAN_TIMEOUT"], filename=filename)
        scan_row = MalwareScan(user_id=current_user.id, filename=filename, size_bytes=size,
                               sha256=digest.hexdigest(), status=scan["status"], engine=scan["engine"],
                               definitions=scan["definitions"], detection=scan["detection"],
                               error=scan["error"], duration_ms=scan["duration_ms"])
        db.session.add(scan_row)
        db.session.flush()
        if scan["status"] != "clean":
            db.session.commit()
            log_event("file_upload_blocked", "critical" if scan["status"] == "infected" else "warning",
                      user=current_user, detail=f"scan={scan_row.id} status={scan['status']}; file not stored or shared")
            flash(f"File was not accepted: scan status {scan['status'].upper()}. {scan['error'] or scan['detection']}", "warning")
            return redirect(url_for("files.page"))
        key = secrets.token_hex(24)
        try:
            put_file(temp_name, key, _storage_root(), "application/octet-stream")
        except Exception:
            db.session.rollback()
            flash("The file passed scanning but private storage failed. Check Supabase Storage configuration and try again.", "warning")
            return redirect(url_for("files.page"))
        record = SharedFile(owner_id=current_user.id, storage_key=key, filename=filename,
                            size_bytes=size, sha256=digest.hexdigest(), scan_status="clean")
        db.session.add(record)
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()
            delete_file(key, _storage_root())
            raise
        log_event("file_uploaded", "info", user=current_user,
                  detail=f"file_id={record.id} scan={scan_row.id} size={size} sha256={record.sha256[:16]}")
        flash("File scanned CLEAN and stored privately. It is not shared until you choose a recipient.", "ok")
        return redirect(url_for("files.page"))
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


@bp.post("/files/<int:file_id>/share")
@login_required
def share(file_id):
    record = SharedFile.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    recipient_names = request.form.getlist("recipients") or [request.form.get("recipient", "")]
    recipient_names = list(dict.fromkeys(name.strip().lower() for name in recipient_names if name.strip()))
    if not recipient_names or len(recipient_names) > 50:
        flash("Select between 1 and 50 registered recipients.", "warning")
        return redirect(url_for("files.page"))
    recipient_query = User.query.filter(User.username.in_(recipient_names), User.id != current_user.id)
    if not current_user.is_admin:
        recipient_query = client_users(recipient_query)
    recipients = recipient_query.all()
    if len(recipients) != len(recipient_names):
        flash("One or more selected recipients are invalid. Choose registered users only.", "warning")
        return redirect(url_for("files.page"))
    if record.scan_status != "clean":
        abort(409)
    already_shared = {share.recipient_id for share in FileShare.query.filter_by(
        file_id=record.id, revoked_at=None).all()}
    new_recipients = [recipient for recipient in recipients if recipient.id not in already_shared]
    if not new_recipients:
        flash("This file is already actively shared with all selected users.", "warning")
        return redirect(url_for("files.page"))
    days = request.form.get("expires_days", "")
    try:
        expiry = (datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=int(days))) if days else None
        if days and not 1 <= int(days) <= 365:
            raise ValueError
    except ValueError:
        flash("Expiry must be between 1 and 365 days.", "warning")
        return redirect(url_for("files.page"))
    for recipient in new_recipients:
        db.session.add(FileShare(file_id=record.id, recipient_id=recipient.id, expires_at=expiry))
    db.session.commit()
    log_event("file_shared", "info", user=current_user,
              detail=f"file_id={record.id} recipient_count={len(new_recipients)} recipient_ids={','.join(str(u.id) for u in new_recipients)}")
    names = ", ".join(recipient.username for recipient in new_recipients)
    flash(f"Shared {record.filename} with {names}.", "ok")
    return redirect(url_for("files.page"))


@bp.post("/files/shares/<int:share_id>/revoke")
@login_required
def revoke(share_id):
    row = FileShare.query.join(SharedFile).filter(FileShare.id == share_id,
                                                  SharedFile.owner_id == current_user.id,
                                                  FileShare.revoked_at.is_(None)).first_or_404()
    row.revoked_at = utcnow()
    db.session.commit()
    log_event("file_share_revoked", "warning", user=current_user,
              detail=f"file_id={row.file_id} share_id={row.id}")
    flash("File share revoked.", "ok")
    return redirect(url_for("files.page"))


@bp.get("/files/<int:file_id>/download")
@login_required
def download(file_id):
    record = SharedFile.query.filter_by(id=file_id).first_or_404()
    is_owner = record.owner_id == current_user.id
    share_row = None if is_owner else _accessible_shares().filter(FileShare.file_id == record.id).first()
    if not is_owner and share_row is None:
        abort(404)
    try:
        content = read_file(record.storage_key, _storage_root())
    except FileNotFoundError:
        abort(404)
    except Exception:
        current_app.logger.exception("Shared file storage read failed for file id %s", record.id)
        abort(503, description="Private file storage is temporarily unavailable.")
    digest = hashlib.sha256(content).hexdigest()
    if not secrets.compare_digest(digest, record.sha256):
        log_event("file_integrity_failure", "critical", user=current_user,
                  detail=f"file_id={record.id} sha256 mismatch; download denied")
        abort(409, description="File integrity verification failed. Download blocked.")
    log_event("file_downloaded", "info", user=current_user,
              detail=f"file_id={record.id} share_id={share_row.id if share_row else 'owner'} integrity=verified")
    return send_file(io.BytesIO(content), as_attachment=True, download_name=record.filename,
                     mimetype="application/octet-stream", max_age=0)


@bp.post("/files/<int:file_id>/verify")
@login_required
def verify(file_id):
    record = SharedFile.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    try:
        actual = hashlib.sha256(read_file(record.storage_key, _storage_root())).hexdigest()
    except FileNotFoundError:
        actual = "missing"
    except Exception:
        current_app.logger.exception("Shared file integrity read failed for file id %s", record.id)
        flash("Private file storage is temporarily unavailable; integrity could not be checked.", "warning")
        return redirect(url_for("files.page"))
    valid = secrets.compare_digest(actual, record.sha256)
    log_event("file_integrity_verified" if valid else "file_integrity_failure",
              "info" if valid else "critical", user=current_user,
              detail=f"file_id={record.id} result={'match' if valid else 'mismatch'}")
    flash("SHA-256 integrity check passed." if valid else "Integrity check failed; do not download this file.",
          "ok" if valid else "warning")
    return redirect(url_for("files.page"))
