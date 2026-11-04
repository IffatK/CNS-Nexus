import csv
import hashlib
import io
import json
import os
import tempfile
from datetime import date, datetime, time, timezone
from pathlib import Path

from flask import Blueprint, abort, current_app, make_response, redirect, render_template, request, url_for, flash
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from extensions import db
from models import MalwareScan, SecurityScan
from models.base import utcnow
from services.analysis_scanner import submit_scan
from services.scanner import file_type_matches, scan_path, scanner_status
from services.security_log import log_event

bp = Blueprint("virus_scanner", __name__)
ALLOWED_EXTENSIONS = {".txt", ".csv", ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip", ".7z"}


def _visible_scans():
    query = MalwareScan.query
    if not current_user.is_admin:
        query = query.filter_by(user_id=current_user.id)
    return query


def _filter_scan_dates(query):
    date_from = (request.args.get("date_from") or "")[:10]
    date_to = (request.args.get("date_to") or "")[:10]
    if bool(date_from) != bool(date_to):
        abort(400, description="Choose both dates for a scan report filter.")
    if date_from:
        try:
            first, last = date.fromisoformat(date_from), date.fromisoformat(date_to)
        except ValueError:
            abort(400, description="Choose valid scan report dates.")
        if last < first or (last - first).days > 365:
            abort(400, description="Choose a date range no longer than 365 days.")
        query = query.filter(MalwareScan.created_at >= datetime.combine(first, time.min),
                             MalwareScan.created_at <= datetime.combine(last, time.max))
    return query


def _clean_csv_cell(value):
    text = str(value or "")
    if text.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text
    return text


@bp.get("/virus-scanner")
@login_required
def page():
    rows = _filter_scan_dates(_visible_scans()).order_by(MalwareScan.id.desc()).limit(100).all()
    binary = current_app.config["CLAMSCAN_PATH"]
    available = scanner_status(binary)["available"]
    return render_template("virus_scanner.html", rows=rows, engine_available=available,
                           virustotal_configured=bool(os.environ.get("VIRUSTOTAL_API_KEY", "").strip()),
                           max_mb=current_app.config["MAX_SCAN_BYTES"] // (1024 * 1024),
                           date_from=request.args.get("date_from", "")[:10], date_to=request.args.get("date_to", "")[:10])


@bp.post("/virus-scanner/scan")
@login_required
def scan_upload():
    upload = request.files.get("file")
    if upload is None or not upload.filename:
        flash("Choose a file to scan.", "warning")
        return redirect(url_for("virus_scanner.page"))
    filename = secure_filename(upload.filename)[:255]
    suffix = Path(filename).suffix.lower()
    if not filename or suffix not in ALLOWED_EXTENSIONS:
        flash("That file type is not supported by the lab scanner.", "warning")
        return redirect(url_for("virus_scanner.page"))

    if request.form.get("upload_file_to_virustotal") == "on":
        if not os.environ.get("VIRUSTOTAL_API_KEY", "").strip():
            flash("Multi-engine scanning is not configured. Add VIRUSTOTAL_API_KEY in the deployment environment.", "warning")
            return redirect(url_for("virus_scanner.page"))
        active = SecurityScan.query.filter_by(user_id=current_user.id).filter(
            SecurityScan.status.in_(("queued", "running"))).count()
        if active >= 2:
            flash("You already have two scans queued or running. Please wait for one to finish.", "warning")
            return redirect(url_for("virus_scanner.page"))
        from services.analysis_scanner import safe_scan_file
        try:
            temp_name, size, digest, mime = safe_scan_file(upload, filename,
                current_app.config["MAX_SCAN_BYTES"], Path(current_app.config["INSTANCE_DIR"]) / "scanner-tmp")
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("virus_scanner.page"))
        if not file_type_matches(temp_name, suffix):
            Path(temp_name).unlink(missing_ok=True)
            flash("The file contents do not match the selected file type.", "warning")
            return redirect(url_for("virus_scanner.page"))
        scan = SecurityScan(user_id=current_user.id, scan_type="file", target=filename,
            status="queued", config_json=json.dumps({"sha256": digest, "size_bytes": size,
                "mime_type": mime, "upload_file_to_virustotal": True, "temp_path": temp_name}))
        db.session.add(scan)
        db.session.commit()
        if not submit_scan(current_app._get_current_object(), scan.id, temp_name):
            scan.status, scan.error, scan.completed_at = "failed", "Scanner queue is full; retry later.", utcnow()
            db.session.commit()
            Path(temp_name).unlink(missing_ok=True)
            flash(scan.error, "warning")
            return redirect(url_for("virus_scanner.page"))
        log_event("security_scan_queued", "info", user=current_user,
                  detail=f"scan_id={scan.id} scan_type=file provider=virustotal")
        return redirect(url_for("security_center.detail", scan_id=scan.id))

    temp_dir = Path(current_app.config["INSTANCE_DIR"]) / "scanner-tmp"
    temp_dir.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix="scan-", suffix=".bin", dir=temp_dir)
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = upload.stream.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > current_app.config["MAX_SCAN_BYTES"]:
                    raise ValueError("File exceeds the configured upload size limit.")
                digest.update(chunk)
                out.write(chunk)
        if not file_type_matches(temp_name, suffix):
            flash("The file contents do not match the selected file type.", "warning")
            return redirect(url_for("virus_scanner.page"))
        scan = scan_path(temp_name, current_app.config["CLAMSCAN_PATH"],
                         current_app.config["CLAMSCAN_TIMEOUT"], filename=filename)
    except ValueError as exc:
        flash(str(exc), "warning")
        return redirect(url_for("virus_scanner.page"))
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass

    row = MalwareScan(user_id=current_user.id, filename=filename, size_bytes=size,
                      sha256=digest.hexdigest(), status=scan["status"], engine=scan["engine"],
                      definitions=scan["definitions"], detection=scan["detection"],
                      error=scan["error"], duration_ms=scan["duration_ms"])
    db.session.add(row)
    db.session.commit()
    severity = "critical" if row.status == "infected" else "warning" if row.status == "failed" else "info"
    log_event("malware_scan_" + row.status, severity, user=current_user,
              detail=f"scan={row.id} file_size={size} sha256={row.sha256[:16]} status={row.status}")
    flash(f"Scan #{row.id}: {row.status.upper()}" + (f" — {row.error}" if row.error else ""),
          "ok" if row.status == "clean" else "warning")
    return redirect(url_for("virus_scanner.page", _anchor=f"scan-{row.id}"))


@bp.get("/virus-scanner/reports.csv")
@login_required
def export_csv():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["scan_id", "timestamp_utc", "filename", "size_bytes", "sha256", "status", "engine", "definitions", "detection", "duration_ms", "error", "report_generated_at_utc", "metric_definition"])
    generated = datetime.now(timezone.utc).isoformat()
    query = _filter_scan_dates(_visible_scans())
    for row in query.order_by(MalwareScan.id.desc()).limit(1000):
        writer.writerow([_clean_csv_cell(value) for value in (
            row.id, row.created_at.isoformat() + "Z", row.filename, row.size_bytes, row.sha256,
            row.status.upper(), row.engine, row.definitions, row.detection, row.duration_ms, row.error,
            generated, "One row per authorized completed scan record; maximum 1000 rows.")])
    response = make_response("\ufeff" + output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=cns-scan-report.csv"
    return response


@bp.get("/virus-scanner/<int:scan_id>")
@login_required
def report(scan_id):
    row = _visible_scans().filter_by(id=scan_id).first()
    if row is None:
        abort(404)
    return render_template("scan_report.html", scan=row)
