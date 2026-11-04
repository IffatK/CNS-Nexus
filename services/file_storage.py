"""Private file storage with Supabase Storage support and local fallback.

Render's local filesystem is ephemeral. Configure SUPABASE_URL and a server-only
Supabase secret key to keep shared file bytes in a private bucket.
"""
import os
import shutil
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _settings():
    base_url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    service_key = (os.environ.get("SUPABASE_SECRET_KEY", "").strip()
                   or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip())
    bucket = os.environ.get("SUPABASE_STORAGE_BUCKET", "cns-shared-files").strip()
    return base_url, service_key, bucket


def uses_supabase_storage():
    base_url, service_key, _ = _settings()
    return bool(base_url and service_key)


def _request(method, url, *, body=None, content_type="application/json"):
    _, service_key, _ = _settings()
    headers = {
        "apikey": service_key,
        "Content-Type": content_type,
        "Accept": "application/json",
    }
    # Current sb_secret keys are API keys, not JWTs; legacy service_role keys
    # are JWTs and still need the Bearer header for Storage authorization.
    if service_key and not service_key.startswith("sb_secret_"):
        headers["Authorization"] = f"Bearer {service_key}"
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read(12 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        # Keep provider responses out of end-user errors and logs.
        raise RuntimeError(f"Supabase Storage request failed (HTTP {exc.code}).") from None


def _bucket_url():
    base_url, _, bucket = _settings()
    return f"{base_url}/storage/v1/bucket/{urllib.parse.quote(bucket, safe='')}"


def _ensure_bucket():
    base_url, _, bucket = _settings()
    try:
        _request("GET", _bucket_url())
        return
    except RuntimeError as exc:
        if "HTTP 404" not in str(exc):
            raise
    # Create a private bucket if it has not been provisioned yet.
    try:
        _request("POST", f"{base_url}/storage/v1/bucket", body=json.dumps({
            "name": bucket, "public": False,
        }).encode("utf-8"))
    except RuntimeError as exc:
        # Another worker may have created it between the lookup and create.
        if "HTTP 409" not in str(exc):
            raise


def put_file(local_path, storage_key, local_root, content_type="application/octet-stream"):
    if uses_supabase_storage():
        base_url, _, bucket = _settings()
        _ensure_bucket()
        key = urllib.parse.quote(storage_key, safe="")
        return _request("POST", f"{base_url}/storage/v1/object/{urllib.parse.quote(bucket, safe='')}/{key}",
                        body=Path(local_path).read_bytes(), content_type=content_type)
    root = Path(local_root).resolve()
    root.mkdir(parents=True, exist_ok=True)
    target = (root / storage_key).resolve()
    if target.parent != root:
        raise ValueError("Invalid file storage key.")
    shutil.copyfile(local_path, target)
    try:
        os.chmod(target, 0o600)
    except OSError:
        pass
    return target


def read_file(storage_key, local_root):
    if uses_supabase_storage():
        base_url, _, bucket = _settings()
        key = urllib.parse.quote(storage_key, safe="")
        url = f"{base_url}/storage/v1/object/{urllib.parse.quote(bucket, safe='')}/{key}"
        return _request("GET", url, content_type="application/octet-stream")
    root = Path(local_root).resolve()
    path = (root / storage_key).resolve()
    if path.parent != root or not path.is_file():
        raise FileNotFoundError(storage_key)
    return path.read_bytes()


def delete_file(storage_key, local_root):
    if uses_supabase_storage():
        base_url, _, bucket = _settings()
        key = urllib.parse.quote(storage_key, safe="")
        url = f"{base_url}/storage/v1/object/{urllib.parse.quote(bucket, safe='')}/{key}"
        try:
            _request("DELETE", url)
        except RuntimeError:
            pass
        return
    root = Path(local_root).resolve()
    path = (root / storage_key).resolve()
    if path.parent == root:
        path.unlink(missing_ok=True)
