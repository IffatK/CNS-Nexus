import hashlib
import os
import secrets
import shutil
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from extensions import db
from models import FileShare, MalwareScan, SharedFile, User
from models.base import utcnow
from services.scanner import file_type_matches, scan_path, scanner_status
from services.security_log import log_event
from services.roles import client_users

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
        target = _storage_root() / key
        shutil.copyfile(temp_name, target)
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
        record = SharedFile(owner_id=current_user.id, storage_key=key, filename=filename,
                            size_bytes=size, sha256=digest.hexdigest(), scan_status="clean")
        db.session.add(record)
        db.session.commit()
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
    path = (_storage_root() / record.storage_key).resolve()
    if path.parent != _storage_root().resolve() or not path.is_file():
        abort(404)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if not secrets.compare_digest(digest, record.sha256):
        log_event("file_integrity_failure", "critical", user=current_user,
                  detail=f"file_id={record.id} sha256 mismatch; download denied")
        abort(409, description="File integrity verification failed. Download blocked.")
    log_event("file_downloaded", "info", user=current_user,
              detail=f"file_id={record.id} share_id={share_row.id if share_row else 'owner'} integrity=verified")
    return send_file(path, as_attachment=True, download_name=record.filename,
                     mimetype="application/octet-stream", max_age=0)


@bp.post("/files/<int:file_id>/verify")
@login_required
def verify(file_id):
    record = SharedFile.query.filter_by(id=file_id, owner_id=current_user.id).first_or_404()
    path = (_storage_root() / record.storage_key).resolve()
    actual = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else "missing"
    valid = secrets.compare_digest(actual, record.sha256)
    log_event("file_integrity_verified" if valid else "file_integrity_failure",
              "info" if valid else "critical", user=current_user,
              detail=f"file_id={record.id} result={'match' if valid else 'mismatch'}")
    flash("SHA-256 integrity check passed." if valid else "Integrity check failed; do not download this file.",
          "ok" if valid else "warning")
    return redirect(url_for("files.page"))
