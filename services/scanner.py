"""Safe, local ClamAV adapter. Uploaded bytes are never executed or persisted here."""
import hashlib
import os
import shutil
import subprocess
import threading
import time
import zipfile
from pathlib import Path

_slots = threading.BoundedSemaphore(2)


def file_type_matches(path, suffix):
    """Small, explicit magic checks for the file types accepted by the UI."""
    with open(path, "rb") as stream:
        head = stream.read(4096)
    if suffix == ".pdf":
        return head.startswith(b"%PDF-")
    if suffix == ".png":
        return head.startswith(b"\x89PNG\r\n\x1a\n")
    if suffix in (".jpg", ".jpeg"):
        return head.startswith(b"\xff\xd8\xff")
    if suffix == ".gif":
        return head.startswith((b"GIF87a", b"GIF89a"))
    if suffix in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".zip"):
        return head.startswith(b"PK\x03\x04") and zipfile.is_zipfile(path)
    if suffix == ".7z":
        return head.startswith(b"7z\xbc\xaf\x27\x1c")
    if suffix in (".txt", ".csv"):
        if b"\x00" in head:
            return False
        try:
            head.decode("utf-8-sig")
            return True
        except UnicodeDecodeError:
            return False
    return False


def sha256_stream(stream, limit):
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise ValueError("File exceeds the configured upload size limit")
        digest.update(chunk)
    return size, digest.hexdigest()


def scanner_status(binary="clamscan"):
    """Probe both the executable and readable virus definitions without scanning user data."""
    if not (shutil.which(binary) or Path(binary).is_file()):
        return {"available": False, "engine": "unavailable", "definitions": "unknown"}
    try:
        result = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                timeout=5, check=False, shell=False)
        if result.returncode != 0 or "/" not in result.stdout:
            return {"available": False, "engine": "unavailable", "definitions": "unavailable"}
        parts = result.stdout.strip().split("/", 2)
        return {"available": True, "engine": parts[0][:120],
                "definitions": parts[1][:120] if len(parts) > 1 else "unknown"}
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "engine": "unavailable", "definitions": "unavailable"}


def _scan_with_daemon(path, binary, timeout, filename):
    """Use the persistent ClamAV daemon when configured and reachable; else fall back."""
    daemon = os.environ.get("CLAMDSCAN_PATH", "clamdscan").strip()
    if not daemon or not (shutil.which(daemon) or Path(daemon).is_file()):
        return None
    try:
        result = subprocess.run([daemon, "--fdpass", "--no-summary", str(path)],
                                capture_output=True, text=True,
                                timeout=min(max(1, timeout), 3), check=False, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (result.stdout + "\n" + result.stderr).strip()
    if result.returncode == 1 and "FOUND" in output:
        detection = next((line.rsplit(": ", 1)[-1].removesuffix(" FOUND")
                          for line in output.splitlines() if " FOUND" in line), "Detection reported")
        status, error, detection = "infected", "", detection[:255]
    elif result.returncode == 0 and (" OK" in output or output.endswith("OK")):
        status, error, detection = "clean", "", ""
    else:
        # An unreachable daemon, inaccessible file, or other daemon error must
        # fall through to the standalone scanner instead of claiming a result.
        return None
    info = scanner_status(binary)
    engine = info["engine"] if info["available"] else "ClamAV daemon"
    definitions = info["definitions"] if info["available"] else "daemon signatures"
    if status == "clean" and Path(filename or path).suffix.lower() in {".docm", ".xlsm", ".pptm"}:
        status, error, detection = "suspicious", "Macro-enabled Office document requires manual review.", "Macro-enabled Office format"
    return {"status": status, "error": error, "engine": engine, "definitions": definitions,
            "detection": detection, "duration_ms": 0}


def scan_path(path, binary="clamscan", timeout=120, filename=None):
    """Return CLEAN/INFECTED/SUSPICIOUS/FAILED with no clean fallback on errors."""
    if not _slots.acquire(blocking=False):
        return {"status": "failed", "error": "Scanner is busy; retry shortly.", "engine": "unknown", "definitions": "unknown", "detection": "", "duration_ms": 0}
    started = time.monotonic()
    try:
        daemon_result = _scan_with_daemon(path, binary, timeout, filename)
        if daemon_result is not None:
            daemon_result["duration_ms"] = int((time.monotonic() - started) * 1000)
            return daemon_result
        version = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                 timeout=min(timeout, 10), check=False, shell=False)
        if version.returncode != 0:
            raise RuntimeError("ClamAV version check failed")
        parts = version.stdout.strip().split("/", 2)
        engine = parts[0][:120]
        definitions = parts[1][:120] if len(parts) > 1 else "unknown"
        result = subprocess.run([binary, "--no-summary", str(path)], capture_output=True,
                                text=True, timeout=timeout, check=False, shell=False)
        duration = int((time.monotonic() - started) * 1000)
        output = (result.stdout + "\n" + result.stderr).strip()
        if result.returncode == 0 and "OK" in output:
            if Path(filename or path).suffix.lower() in {".docm", ".xlsm", ".pptm"}:
                return {"status": "suspicious", "error": "Macro-enabled Office document requires manual review.",
                        "engine": engine, "definitions": definitions, "detection": "Macro-enabled Office format",
                        "duration_ms": duration}
            return {"status": "clean", "error": "", "engine": engine, "definitions": definitions,
                    "detection": "", "duration_ms": duration}
        if result.returncode == 1 and "FOUND" in output:
            detection = next((line.rsplit(": ", 1)[-1].removesuffix(" FOUND")
                              for line in output.splitlines() if " FOUND" in line), "Detection reported")
            return {"status": "infected", "error": "", "engine": engine, "definitions": definitions,
                    "detection": detection[:255], "duration_ms": duration}
        return {"status": "failed", "error": "ClamAV could not complete a trustworthy scan.",
                "engine": engine, "definitions": definitions, "detection": "", "duration_ms": duration}
    except FileNotFoundError:
        error = "ClamAV is unavailable. Install clamav and clamav-freshclam, then update signatures."
    except subprocess.TimeoutExpired:
        error = "The malware scan exceeded its configured time limit."
    except Exception:
        error = "The scanner failed; no clean result was produced."
    return {"status": "failed", "error": error, "engine": "unavailable", "definitions": "unknown",
            "detection": "", "duration_ms": int((time.monotonic() - started) * 1000)}


def scan_path_cancellable(path, binary="clamscan", timeout=30, filename=None, cancel_check=None):
    """ClamAV adapter used by background jobs; polls cancellation and hard timeout."""
    started = time.monotonic()
    if not (shutil.which(binary) or Path(binary).is_file()):
        return {"status": "failed", "error": "ClamAV is unavailable; no clean result was produced.",
                "engine": "unavailable", "definitions": "unknown", "detection": "", "duration_ms": 0}
    proc = None
    try:
        version = subprocess.run([binary, "--version"], capture_output=True, text=True,
                                 timeout=min(max(1, timeout), 10), check=False, shell=False)
        if version.returncode != 0 or "/" not in version.stdout:
            raise RuntimeError("ClamAV version check failed")
        parts = version.stdout.strip().split("/", 2)
        engine = parts[0][:120]
        definitions = parts[1][:120] if len(parts) > 1 else "unknown"
        proc = subprocess.Popen([binary, "--no-summary", str(path)], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, shell=False)
        deadline = time.monotonic() + max(1, timeout)
        while proc.poll() is None:
            try:
                should_cancel = bool(cancel_check and cancel_check())
            except Exception:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=1)
                raise
            if should_cancel:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=1)
                return {"status": "cancelled", "error": "Cancelled by the user.", "engine": engine,
                        "definitions": definitions, "detection": "", "duration_ms": int((time.monotonic()-started)*1000)}
            if time.monotonic() >= deadline:
                proc.terminate()
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=1)
                return {"status": "failed", "error": "The malware scan exceeded its configured time limit.",
                        "engine": engine, "definitions": definitions, "detection": "",
                        "duration_ms": int((time.monotonic()-started)*1000)}
            time.sleep(.05)
        stdout, stderr = proc.communicate(timeout=1)
        output = (stdout + "\n" + stderr).strip()
        duration = int((time.monotonic()-started)*1000)
        if proc.returncode == 0 and "OK" in output:
            if Path(filename or path).suffix.lower() in {".docm", ".xlsm", ".pptm"}:
                return {"status":"suspicious","error":"Macro-enabled Office document requires manual review.","engine":engine,"definitions":definitions,"detection":"Macro-enabled Office format","duration_ms":duration}
            return {"status":"clean","error":"","engine":engine,"definitions":definitions,"detection":"","duration_ms":duration}
        if proc.returncode == 1 and "FOUND" in output:
            detection = next((line.rsplit(": ", 1)[-1].removesuffix(" FOUND") for line in output.splitlines() if " FOUND" in line), "Detection reported")
            return {"status":"infected","error":"","engine":engine,"definitions":definitions,"detection":detection[:255],"duration_ms":duration}
        return {"status":"failed","error":"ClamAV could not complete a trustworthy scan.","engine":engine,"definitions":definitions,"detection":"","duration_ms":duration}
    except FileNotFoundError:
        error = "ClamAV is unavailable; no clean result was produced."
    except subprocess.TimeoutExpired:
        if proc and proc.poll() is None:
            proc.kill(); proc.wait()
        error = "The malware scan exceeded its configured time limit."
    except Exception:
        error = "The scanner failed; no clean result was produced."
    return {"status":"failed","error":error,"engine":"unavailable","definitions":"unknown","detection":"","duration_ms":int((time.monotonic()-started)*1000)}
