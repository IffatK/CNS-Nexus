"""Bounded, non-destructive scanner primitives for the authenticated security center."""
from __future__ import annotations

import http.client
import ipaddress
import json
import mimetypes
import os
import re
import secrets
import socket
import shutil
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from flask import current_app

from extensions import db
from models import SecurityFinding, SecurityScan, SharedFile, User
from models.base import utcnow
from services.security_log import log_event

SEVERITY_POINTS = {"critical": 100, "high": 75, "medium": 50, "low": 25, "informational": 0}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
MAX_RESPONSE_BYTES = 256 * 1024
MAX_URL_LENGTH = 2048
MAX_REDIRECTS = 4
_pool = None
_pool_lock = threading.Lock()
_slots = threading.BoundedSemaphore(4)
_cancellations: dict[int, threading.Event] = {}
_cancel_lock = threading.Lock()


class ScanCancelled(Exception):
    pass


class ScanTimedOut(Exception):
    pass


class UnsafeTarget(ValueError):
    pass


def normalize_target(value: str) -> tuple[str, str, int, str]:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > MAX_URL_LENGTH:
        raise UnsafeTarget("Enter a URL no longer than 2048 characters.")
    raw = value.strip()
    if any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise UnsafeTarget("Control characters are not allowed in a URL.")
    try:
        parts = urllib.parse.urlsplit(raw)
        scheme = parts.scheme.lower()
        if scheme not in ("http", "https"):
            raise UnsafeTarget("Only HTTP and HTTPS URLs are supported.")
        if parts.username is not None or parts.password is not None:
            raise UnsafeTarget("URLs containing embedded credentials are not accepted.")
        host = parts.hostname
        if not host:
            raise UnsafeTarget("The URL must include a hostname.")
        try:
            host_ascii = host.encode("idna").decode("ascii").lower().rstrip(".")
        except UnicodeError as exc:
            raise UnsafeTarget("The hostname could not be normalized.") from exc
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        if isinstance(exc, UnsafeTarget):
            raise
        raise UnsafeTarget("The URL syntax or port is invalid.") from exc
    if port not in (80, 443):
        raise UnsafeTarget("Only standard HTTP (80) and HTTPS (443) ports are allowed.")
    try:
        ipaddress.ip_address(host_ascii)
        is_ip = True
    except ValueError:
        is_ip = False
    if (not is_ip and not re.fullmatch(r"[a-z0-9.-]+", host_ascii)) or len(host_ascii) > 253:
        raise UnsafeTarget("The hostname contains unsupported characters.")
    if host_ascii in {"localhost", "localhost.localdomain", "metadata.google.internal"} or host_ascii.endswith((".localhost", ".local", ".internal", ".test")):
        raise UnsafeTarget("Local and internal hostnames are blocked.")
    if is_ip:
        ip = ipaddress.ip_address(host_ascii)
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise UnsafeTarget("Private, local, link-local, and reserved IP targets are blocked.")
    path = urllib.parse.quote(parts.path or "/", safe="/%:@!$&'()*+,;=-._~")
    authority = f"[{host_ascii}]" if ":" in host_ascii else host_ascii
    if port != (443 if scheme == "https" else 80):
        authority += f":{port}"
    normalized = urllib.parse.urlunsplit((scheme, authority, path, parts.query, ""))
    return normalized, scheme, port, host_ascii


def _resolve_public(host: str, port: int) -> list[str]:
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            addresses = list(dict.fromkeys(item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
        except OSError as exc:
            raise UnsafeTarget("Hostname resolution failed.") from exc
    if not addresses:
        raise UnsafeTarget("Hostname has no usable addresses.")
    for value in addresses:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
        if not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise UnsafeTarget("The target resolves to a private, local, reserved, or otherwise non-public address.")
    return addresses


def _blocked_hosts(extra=()):
    result = set()
    for item in (current_app.config.get("SERVER_NAME"), current_app.config.get("SCANNER_BLOCKED_HOSTS", "")):
        if not item:
            continue
        for host in str(item).replace(",", " ").split():
            result.add(host.split(":", 1)[0].strip("[]").lower())
    result.update(str(host).strip("[]").lower() for host in extra if host)
    return result


class _PinnedHTTPS(http.client.HTTPSConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port=port, timeout=timeout, context=ssl.create_default_context())
        self._pinned_address = address

    def connect(self):
        raw = socket.create_connection((self._pinned_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, address, port, timeout):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_address = address

    def connect(self):
        self.sock = socket.create_connection((self._pinned_address, self.port), self.timeout)


def safe_fetch(url: str, *, cancel_check=None, max_redirects=MAX_REDIRECTS, max_bytes=MAX_RESPONSE_BYTES, allowed_host=None, blocked_hosts=()):
    """Fetch one public HTTP resource using a validated, DNS-pinned connection."""
    chain, total_read = [], 0
    current = url
    for _ in range(max_redirects + 1):
        if cancel_check and cancel_check():
            raise ScanCancelled()
        normalized, scheme, port, host = normalize_target(current)
        if host in _blocked_hosts(blocked_hosts):
            raise UnsafeTarget("The scanner's own host is blocked as a target.")
        if allowed_host and host != allowed_host:
            raise UnsafeTarget("Redirect left the explicitly authorized hostname scope.")
        addresses = _resolve_public(host, port)
        address = addresses[0]
        parts = urllib.parse.urlsplit(normalized)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        cls = _PinnedHTTPS if scheme == "https" else _PinnedHTTP
        connection = cls(host, address, port, timeout=3.0)
        try:
            connection.request("GET", path, headers={
                "Host": parts.netloc, "User-Agent": "CNS-Security-Lab-Scanner/1.0",
                "Accept": "text/html,application/json,text/plain,*/*;q=0.2",
                "Accept-Encoding": "identity", "Connection": "close",
            })
            response = connection.getresponse()
            raw_headers = response.getheaders()
            headers = {key.lower(): value[:2000] for key, value in raw_headers if key.lower() in {
                "content-type", "content-length", "location", "server", "x-powered-by",
                "content-security-policy", "strict-transport-security", "x-content-type-options",
                "referrer-policy", "permissions-policy", "x-frame-options", "access-control-allow-origin",
                "access-control-allow-credentials", "set-cookie", "content-disposition",
            }}
            cookies = [value[:2000] for key, value in raw_headers if key.lower() == "set-cookie"]
            if cookies:
                headers["set-cookie"] = "\n".join(cookies)
            cert = None
            tls_version, tls_cipher = None, None
            if scheme == "https" and connection.sock:
                cert = connection.sock.getpeercert()
                tls_version = connection.sock.version()
                cipher = connection.sock.cipher()
                tls_cipher = cipher[0] if cipher else None
            status = response.status
            location = response.getheader("Location")
            chain.append({"url": _url_without_query(normalized), "status": status,
                          "host": host, "address": address})
            if status in (301, 302, 303, 307, 308) and location:
                if len(chain) > max_redirects:
                    raise UnsafeTarget("Redirect limit reached.")
                current = urllib.parse.urljoin(normalized, location)
                if scheme == "https" and urllib.parse.urlsplit(current).scheme.lower() == "http":
                    chain[-1]["downgrade"] = True
                continue
            declared = response.getheader("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                response.close()
                return {"url": normalized, "status": status, "headers": headers, "body": b"",
                        "truncated": True, "redirects": chain, "content_length": int(declared),
                        "certificate": cert, "tls_verified": scheme == "https",
                        "tls_version": tls_version, "tls_cipher": tls_cipher}
            chunks = []
            while total_read < max_bytes:
                if cancel_check and cancel_check():
                    raise ScanCancelled()
                chunk = response.read(min(8192, max_bytes - total_read))
                if not chunk:
                    break
                total_read += len(chunk)
                chunks.append(chunk)
            return {"url": normalized, "status": status, "headers": headers, "body": b"".join(chunks),
                    "truncated": total_read >= max_bytes, "redirects": chain,
                    "content_length": int(declared) if declared and declared.isdigit() else total_read,
                    "certificate": cert, "tls_verified": scheme == "https",
                    "tls_version": tls_version, "tls_cipher": tls_cipher}
        finally:
            connection.close()
    raise UnsafeTarget("Redirect limit reached.")


def _url_without_query(url):
    parts = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "[query omitted]" if parts.query else "", ""))


def _is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _finding(key, title, severity, confidence, category, affected, evidence, explanation,
             impact, remediation, source="local heuristic", verification="observed"):
    remediation_steps = [remediation]
    verification_steps = ["Re-run the applicable check after remediation and confirm the observed condition has changed.",
                          "Review application behavior and logs to ensure the change did not break intended functionality."]
    return {"key": key, "title": title, "severity": severity, "confidence": confidence,
            "category": category, "affected": _url_without_query(affected) if affected.startswith(("http://", "https://")) else affected,
            "evidence": evidence[:1200], "explanation": explanation, "impact": impact,
            "remediation": remediation, "remediation_steps_json": json.dumps(remediation_steps),
            "verification_steps_json": json.dumps(verification_steps),
            "source": source, "verification": verification}


def _body_text(response):
    charset = "utf-8"
    content_type = response["headers"].get("content-type", "")
    match = re.search(r"charset=([\w.-]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    try:
        return response["body"].decode(charset, errors="replace")
    except LookupError:
        return response["body"].decode("utf-8", errors="replace")


def _url_findings(target, response=None):
    normalized, scheme, _, host = normalize_target(target)
    parts = urllib.parse.urlsplit(normalized)
    findings = []
    indicators = []
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_global:
            indicators.append("URL uses a literal public IP address.")
    except ValueError:
        if host.startswith("xn--") or ".xn--" in host:
            indicators.append("Hostname contains an IDN/punycode label.")
        if len(host.split(".")) >= 5:
            indicators.append("Hostname has an unusually deep subdomain chain.")
    if "@" in (parts.path + parts.query) or re.search(r"%25|%2f|%5c", normalized, re.I):
        indicators.append("URL contains userinfo-like or double-encoded path patterns.")
    if re.search(r"(?:login|verify|wallet|password|account|secure|update)[-_].{0,20}(?:login|verify|wallet|password|account|secure|update)", host, re.I):
        indicators.append("Hostname combines common account/security lures.")
    if indicators:
        findings.append(_finding("url-patterns", "Suspicious URL patterns observed", "medium", "low", "url-pattern",
            normalized, " ".join(indicators), "These are heuristic indicators and do not prove that the URL is malicious.",
            "The URL may be designed to appear trustworthy or obscure its destination.",
            "Verify the domain through a trusted channel and avoid entering credentials unless the destination is confirmed."))
    if response is not None:
        if len(response["redirects"]) > 1:
            findings.append(_finding("redirect-chain", "Redirect chain observed", "informational", "high", "url-redirect",
                normalized, json.dumps(response["redirects"]), "The scanner followed a bounded redirect chain and revalidated each destination.",
                "Redirects can obscure the final destination.", "Confirm each redirect target is expected."))
        if response["status"] >= 400:
            findings.append(_finding("http-status", f"HTTP response returned {response['status']}", "informational", "high", "url-response",
                normalized, f"HTTP status {response['status']}", "The server returned an error or access-control response.",
                "This response alone does not indicate that the target is malicious.", "Review the destination and response in context."))
        ctype = response["headers"].get("content-type", "unknown")
        if any(x in ctype.lower() for x in ("application/octet-stream", "application/x-msdownload", "application/zip")):
            findings.append(_finding("download-content", "URL serves a download-oriented content type", "low", "high", "url-content",
                normalized, f"Content-Type: {ctype}; no content was executed or saved.", "The response advertises a downloadable or binary payload.",
                "Downloaded content may be unsafe if opened.", "Do not open unexpected downloads; scan files with an updated malware scanner."))
        if "index of /" in _body_text(response).lower()[:10000]:
            findings.append(_finding("directory-listing", "Potential directory listing exposed", "medium", "medium", "exposure",
                normalized, "Response body contains a common directory-index marker.", "A directory index may disclose files and application structure.",
                "Exposed files can reveal sensitive data or facilitate further attacks.", "Disable directory indexing and restrict access to non-public files."))
    return findings


def _header_findings(target, response):
    h = response["headers"]
    findings = []
    html_context = "text/html" in h.get("content-type", "").lower()
    checks = [
        ("x-content-type-options", "X-Content-Type-Options", "low", "This header helps prevent MIME-type sniffing."),
        ("referrer-policy", "Referrer-Policy", "low", "A referrer policy limits URL data sent to other sites."),
        ("permissions-policy", "Permissions-Policy", "low", "This header can restrict browser features such as camera and geolocation."),
    ]
    if html_context:
        checks.insert(0, ("content-security-policy", "Content-Security-Policy", "medium", "A CSP can reduce the impact of injected scripts and framing attacks."))
    for key, title, severity, impact in checks:
        if not h.get(key):
            findings.append(_finding("header-"+key, f"Missing {title}", severity, "high", "security-header", target,
                f"No {title} response header was observed.", "The scanner inspected the HTTP response headers only.", impact,
                f"Configure an appropriate {title} header for the application."))
    csp = h.get("content-security-policy", "").lower()
    if html_context and csp and any(marker in csp for marker in ("'unsafe-inline'", "'unsafe-eval'", "default-src *", "script-src *")):
        findings.append(_finding("weak-csp", "Content-Security-Policy contains broad directives", "medium", "high", "security-header", target,
            "Observed CSP includes unsafe-inline, unsafe-eval, or a wildcard source.", "Broad policy directives reduce the protection CSP can provide against script injection.",
            "Injected script may execute despite the presence of a policy.", "Replace broad sources with explicit trusted origins and nonces or hashes."))
    hsts = h.get("strict-transport-security", "").lower()
    max_age = re.search(r"max-age\s*=\s*(\d+)", hsts)
    if hsts and (not max_age or int(max_age.group(1)) < 31536000):
        findings.append(_finding("weak-hsts", "Strict-Transport-Security max-age is short or missing", "low", "high", "security-header", target,
            f"Observed value: {hsts[:160]}", "Short HSTS duration provides less persistent HTTPS enforcement.",
            "Users may be exposed to downgrade paths after the policy expires.", "After validating HTTPS on all subdomains, use an appropriately long max-age."))
    if h.get("x-content-type-options") and h["x-content-type-options"].strip().lower() != "nosniff":
        findings.append(_finding("weak-x-content-type-options", "X-Content-Type-Options is not nosniff", "low", "high", "security-header", target,
            f"Observed value: {h['x-content-type-options'][:100]}", "The header is present but does not use the expected nosniff directive.",
            "Some clients may infer content types unexpectedly.", "Set X-Content-Type-Options: nosniff."))
    frame = h.get("x-frame-options", "").lower()
    csp = h.get("content-security-policy", "").lower()
    if html_context and "frame-ancestors" not in csp and frame not in ("deny", "sameorigin"):
        findings.append(_finding("header-framing", "No framing restriction observed", "medium", "high", "security-header", target,
            "Neither CSP frame-ancestors nor X-Frame-Options DENY/SAMEORIGIN was observed.",
            "Framing restrictions help mitigate clickjacking.", "Users may be tricked into interacting with the site inside an attacker-controlled frame.",
            "Set CSP frame-ancestors to the required trusted origins; use X-Frame-Options for legacy clients."))
    if urllib.parse.urlsplit(target).scheme == "https" and "strict-transport-security" not in h:
        findings.append(_finding("header-hsts", "Missing Strict-Transport-Security", "medium", "high", "security-header", target,
            "HTTPS response did not include Strict-Transport-Security.", "HSTS tells browsers to prefer HTTPS on future visits.",
            "Without HSTS, users may be exposed to downgrade attacks on later visits.", "Enable HSTS after HTTPS is configured correctly across the host."))
    if urllib.parse.urlsplit(target).scheme == "http":
        findings.append(_finding("http-transport", "Website was reached over HTTP", "high", "high", "transport", target,
            "The submitted origin uses HTTP; transport encryption was not present.", "HTTP does not protect traffic from network observers or modification.",
            "Credentials and content may be exposed or altered in transit.", "Serve the site over HTTPS and redirect HTTP to HTTPS."))
    if h.get("access-control-allow-origin") == "*" and h.get("access-control-allow-credentials", "").lower() == "true":
        findings.append(_finding("cors-wildcard-credentials", "Potentially unsafe cross-origin policy", "high", "high", "cors", target,
            "Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true were observed.",
            "Browsers reject this exact combination for credentialed requests, but it suggests a misconfigured CORS policy.",
            "Related permissive rules may expose authenticated responses to other origins.", "Use an explicit allowlist and avoid wildcard origins for credentialed requests."))
    for header in ("server", "x-powered-by"):
        if h.get(header):
            findings.append(_finding("disclosure-"+header, f"Technology banner exposed ({header})", "informational", "high", "information-disclosure", target,
                f"{header}: {h[header][:160]}", "The response reveals server or framework identification.",
                "Version detail can help attackers prioritize known issues.", "Remove or minimize unnecessary product and version banners."))
    cookie_flags = []
    cookies = response["headers"].get("set-cookie", "").splitlines()
    # Only cookie names and missing flags are persisted; values are discarded.
    for cookie in cookies:
        attrs = cookie.lower()
        name = cookie.split("=", 1)[0][:80]
        missing = [flag for flag, token in (("Secure", "; secure"), ("HttpOnly", "; httponly"), ("SameSite", "; samesite=")) if token not in attrs]
        if missing:
            cookie_flags.append(f"{name}: missing {', '.join(missing)}")
    if cookie_flags:
        findings.append(_finding("cookie-flags", "Cookie security attributes need review", "medium", "high", "cookie", target,
            "; ".join(cookie_flags), "Only cookie attribute names and flags were inspected; cookie values are not persisted.",
            "Weak cookie attributes can increase exposure to theft or cross-site request risks.", "Set Secure, HttpOnly, and an appropriate SameSite attribute on session cookies."))
    return findings


def _reputation_check(url, allowed):
    key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not key:
        return {"provider": "Google Safe Browsing", "status": "not_configured", "detail": "No API key configured; local checks only."}, []
    if not allowed:
        return {"provider": "Google Safe Browsing", "status": "skipped_consent", "detail": "URL was not submitted to the provider because the user did not opt in."}, []
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" + urllib.parse.quote(key, safe="")
    payload = {"client": {"clientId": "cns-security-lab", "clientVersion": "1.0"},
               "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                              "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url}]}}
    req = urllib.request.Request(endpoint, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read(128 * 1024) or b"{}")
        matches = data.get("matches", [])
        if matches:
            return {"provider": "Google Safe Browsing", "status": "match", "detail": f"Provider returned {len(matches)} threat match(es)."}, [
                _finding("reputation-match", "Threat-intelligence provider reported a match", "high", "high", "reputation", url,
                         "; ".join(sorted({str(x.get("threatType", "unknown")) for x in matches})),
                         "Google Safe Browsing reported this URL in a configured threat category.",
                         "The provider classified the URL as a potential malware or social-engineering destination.",
                         "Do not visit or enter information; report the URL to the relevant security team.", "Google Safe Browsing", "provider-match")]
        return {"provider": "Google Safe Browsing", "status": "no_match", "detail": "No match was returned; this does not prove the URL is harmless."}, []
    except Exception as exc:
        return {"provider": "Google Safe Browsing", "status": "unavailable", "detail": f"Provider check failed ({type(exc).__name__}); local checks only."}, []


def _file_result(path, scan_id, cancel_check):
    scan = db.session.get(SecurityScan, scan_id)
    scan_config = json.loads(scan.config_json or "{}")
    if scan_config.get("upload_file_to_virustotal"):
        external = _virustotal_file_scan(path, scan.target, scan_config.get("sha256", ""), cancel_check,
                                         lambda progress: _set_progress(scan_id, progress))
        if external.get("status") in ("completed", "pending"):
            detections = external.get("malicious", 0) + external.get("suspicious", 0)
            is_bad = external.get("malicious", 0) > 0
            is_suspicious = external.get("suspicious", 0) > 0
            scan_status = "infected" if is_bad else "suspicious" if is_suspicious else "clean"
            if external["status"] == "pending":
                scan_status = "failed"
            title = ("VirusTotal multi-engine analysis detected malware" if is_bad else
                     "VirusTotal engines reported suspicious content" if is_suspicious else
                     "No VirusTotal engine detection reported" if external["status"] == "completed" else
                     "VirusTotal analysis is still pending")
            severity = "critical" if is_bad else "medium" if is_suspicious or external["status"] == "pending" else "informational"
            evidence = (f"{external.get('malicious', 0)} malicious, {external.get('suspicious', 0)} suspicious, "
                        f"{external.get('undetected', 0)} undetected across {external.get('engine_count', 0)} engines.")
            if external.get("engine_names"):
                evidence += " Detections: " + ", ".join(external["engine_names"][:5]) + "."
            if external["status"] == "pending":
                evidence = "VirusTotal accepted the sample but analysis was not complete before the bounded wait ended. No clean verdict is available."
            findings = [_finding("virustotal-multiengine", title, severity,
                "high" if external["status"] == "completed" else "low", "malware", scan.target, evidence,
                "This sample was uploaded to VirusTotal for analysis by its participating engines; submissions are added to its shared dataset.",
                "A detection may be a false positive; a no-detection result does not prove the file is harmless.",
                "Quarantine detected samples. For pending or inconclusive results, wait for the provider report or use an updated local scanner.",
                "VirusTotal multi-engine", "engine-detection" if detections else "observed")]
            details = {"sha256": scan_config.get("sha256", ""), "mime_type": scan_config.get("mime_type", "application/octet-stream"),
                       "file_size": Path(path).stat().st_size, "scanner": {"status": scan_status,
                       "engine": "VirusTotal multi-engine", "definitions": f"{external.get('engine_count', 0)} engines",
                       "detection": evidence if detections else "", "error": "" if external["status"] == "completed" else evidence,
                       "duration_ms": external.get("duration_ms", 0)}, "engines": ["VirusTotal multi-engine"],
                       "reputation": external, "limitations": ["The file sample was submitted to VirusTotal and may be shared with its security partners; the provider may inspect archive contents.",
                       "A clean result is not a guarantee of safety."]}
            return findings, details, "completed" if external["status"] == "completed" else "partial"
        # Keep fail-closed behavior, but use local ClamAV as a fallback when it exists.
        provider_error = external.get("detail", "VirusTotal upload failed.")
    else:
        provider_error = ""
    from services.scanner import scan_path_cancellable
    result = scan_path_cancellable(path, current_app.config["CLAMSCAN_PATH"],
                       scan_config.get("scanner_timeout_seconds", min(current_app.config["CLAMSCAN_TIMEOUT"], 30)),
                       filename=scan.target, cancel_check=cancel_check)
    mime, _ = mimetypes.guess_type(scan.target)
    findings = []
    severity = {"infected": "critical", "suspicious": "medium", "failed": "medium", "clean": "informational"}.get(result["status"], "medium")
    title = {"infected": "Malware detected by ClamAV", "suspicious": "File requires manual review",
             "failed": "File scan incomplete", "clean": "No detection from configured scanner"}.get(result["status"], "File scan failed")
    evidence = result.get("detection") or result.get("error") or f"ClamAV {result['engine']} / definitions {result['definitions']} returned no detection."
    if provider_error:
        evidence = f"VirusTotal unavailable ({provider_error}); local result: {evidence}"
    findings.append(_finding("file-engine-result", title, severity,
        "high" if result["status"] in ("infected", "clean") else "low", "malware", scan.target, evidence,
        "ClamAV result applies only to the configured engine and its installed signatures.",
        "A detection indicates malicious content; a clean result does not establish that a file is harmless.",
        "Quarantine detections. For incomplete or suspicious results, use updated scanners and analyst review.",
        result.get("engine", "ClamAV"), "engine-detection" if result["status"] == "infected" else "observed"))
    digest = scan_config.get("sha256", "")
    reputation, rep_findings = _file_hash_reputation(digest, bool(scan_config.get("share_file_hash")))
    findings.extend(rep_findings)
    details = {"sha256": digest, "mime_type": mime or "application/octet-stream",
               "scanner": result, "file_size": Path(path).stat().st_size, "engines": [result.get("engine", "ClamAV")],
               "reputation": reputation,
               "limitations": ["The file was not executed or extracted.", "A clean result is not a guarantee of safety."]}
    return findings, details, "completed" if result["status"] in ("clean", "infected", "suspicious") else "partial"


def _virustotal_file_scan(path, filename, digest, cancel_check, update):
    """Submit an explicitly consented sample and perform a small bounded number of status checks."""
    import secrets
    started = time.monotonic()
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"status": "unavailable", "detail": "VirusTotal API key is not configured."}
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(filename).name)[:180] or "sample.bin"
    boundary = "----CNSScan" + secrets.token_hex(16)
    with open(path, "rb") as sample:
        content = sample.read()
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{safe_name}\"\r\n"
            "Content-Type: application/octet-stream\r\n\r\n").encode("ascii") + content + f"\r\n--{boundary}--\r\n".encode("ascii")
    upload = urllib.request.Request("https://www.virustotal.com/api/v3/files", data=body,
        headers={"x-apikey": key, "Accept": "application/json", "Content-Type": f"multipart/form-data; boundary={boundary}"}, method="POST")
    analysis_id = ""
    try:
        if cancel_check():
            raise ScanCancelled()
        with urllib.request.urlopen(upload, timeout=20) as response:
            payload = json.loads(response.read(128 * 1024) or b"{}")
        analysis_id = str(payload.get("data", {}).get("id", ""))
        if not analysis_id:
            return {"status": "unavailable", "detail": "VirusTotal did not return an analysis identifier."}
        update(45)
        data = {}
        for progress in (65, 82):
            if cancel_check():
                raise ScanCancelled()
            time.sleep(8)
            req = urllib.request.Request(f"https://www.virustotal.com/api/v3/analyses/{urllib.parse.quote(analysis_id, safe='')}",
                headers={"x-apikey": key, "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=15) as response:
                data = json.loads(response.read(256 * 1024) or b"{}")
            attrs = data.get("data", {}).get("attributes", {})
            update(progress)
            if attrs.get("status") == "completed":
                stats = attrs.get("stats", {})
                results = attrs.get("results", {})
                hits = [str(item.get("engine_name") or name) for name, item in results.items()
                        if item.get("category") in ("malicious", "suspicious")]
                return {"provider": "VirusTotal", "status": "completed", "analysis_id": analysis_id,
                    "report_url": f"https://www.virustotal.com/gui/file/{digest}",
                    "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
                    "undetected": int(stats.get("undetected", 0)), "engine_count": len(results),
                    "engine_names": hits[:5], "duration_ms": int((time.monotonic()-started)*1000)}
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("stats", {})
        return {"provider": "VirusTotal", "status": "pending", "analysis_id": analysis_id,
            "report_url": f"https://www.virustotal.com/gui/file/{digest}",
            "malicious": int(stats.get("malicious", 0)), "suspicious": int(stats.get("suspicious", 0)),
            "undetected": int(stats.get("undetected", 0)), "engine_count": len(attrs.get("results", {})),
            "engine_names": [], "duration_ms": int((time.monotonic()-started)*1000)}
    except ScanCancelled:
        raise
    except urllib.error.HTTPError as exc:
        if analysis_id:
            return {"provider": "VirusTotal", "status": "pending", "analysis_id": analysis_id,
                "report_url": f"https://www.virustotal.com/gui/file/{digest}", "detail": f"Analysis submitted; status lookup returned HTTP {exc.code}.",
                "malicious": 0, "suspicious": 0, "undetected": 0, "engine_count": 0,
                "engine_names": [], "duration_ms": int((time.monotonic()-started)*1000)}
        return {"status": "unavailable", "detail": f"VirusTotal returned HTTP {exc.code}."}
    except Exception as exc:
        if analysis_id:
            return {"provider": "VirusTotal", "status": "pending", "analysis_id": analysis_id,
                "report_url": f"https://www.virustotal.com/gui/file/{digest}", "detail": f"Analysis submitted; status lookup failed ({type(exc).__name__}).",
                "malicious": 0, "suspicious": 0, "undetected": 0, "engine_count": 0,
                "engine_names": [], "duration_ms": int((time.monotonic()-started)*1000)}
        return {"status": "unavailable", "detail": f"VirusTotal scan failed ({type(exc).__name__})."}
def _file_hash_reputation(digest, consent):
    key = os.environ.get("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        return {"provider": "VirusTotal", "status": "not_configured", "detail": "No API key configured; local scan only."}, []
    if not consent:
        return {"provider": "VirusTotal", "status": "skipped_consent", "detail": "File hash was not submitted; user consent was not given."}, []
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{digest}",
                                 headers={"x-apikey": key, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=4) as response:
            data = json.loads(response.read(128 * 1024) or b"{}")
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        if malicious or suspicious:
            sev = "high" if malicious else "medium"
            finding = _finding("file-reputation", "File hash has threat-intelligence detections", sev, "medium", "reputation",
                digest, f"VirusTotal reports malicious={malicious}, suspicious={suspicious}.",
                "Multiple independent engines may classify a file hash as suspicious or malicious.",
                "The file may pose a malware risk; reputation results can include false positives.",
                "Do not distribute the file. Review the provider report and an updated local scanner.", "VirusTotal", "provider-match")
            return {"provider":"VirusTotal","status":"match","malicious":malicious,"suspicious":suspicious}, [finding]
        return {"provider":"VirusTotal","status":"no_match","malicious":0,"suspicious":0,
                "detail":"No current detection was returned; this does not prove the file is safe."}, []
    except urllib.error.HTTPError as exc:
        status = "not_found" if exc.code == 404 else "unavailable"
        return {"provider":"VirusTotal","status":status,"detail":"Hash lookup did not return an available analysis."}, []
    except Exception as exc:
        return {"provider":"VirusTotal","status":"unavailable","detail":f"Hash lookup failed ({type(exc).__name__})."}, []


def _url_result(scan_id, cancel_check, update):
    scan = db.session.get(SecurityScan, scan_id)
    target = scan.target
    findings = _url_findings(target)
    _, scheme, port, host = normalize_target(target)
    scan_config = json.loads(scan.config_json or "{}")
    blocked_hosts = scan_config.get("blocked_hosts", [])
    if host in _blocked_hosts(blocked_hosts):
        raise UnsafeTarget("The scanner's own host is blocked as a target.")
    # Do not disclose private/internal URLs to reputation providers, even if a user opted in.
    try:
        _resolve_public(host, port)
    except UnsafeTarget as exc:
        findings.append(_finding("target-blocked", "Target blocked by network safety policy", "informational", "high", "scan-limitation",
            target, "Hostname did not resolve exclusively to public, globally routable addresses; no remote request or reputation lookup was made.",
            "Private and internal destinations are blocked to prevent server-side request forgery.",
            "No remote target data was accessed.", "Use an authorized public website or review local files with File Scan."))
        return findings, {"reputation": {"provider": "not contacted", "status": "skipped_private_target",
                 "detail": "Reputation check was skipped because target validation failed."},
                 "engines": ["local URL heuristics", "SSRF destination policy"],
                 "limitations": ["Network and reputation checks were skipped for a blocked target."]}, "partial"
    reputation, rep_findings = _reputation_check(target, scan.consent_reputation)
    findings.extend(rep_findings)
    update(30)
    try:
        response = safe_fetch(target, cancel_check=cancel_check, allowed_host=host, blocked_hosts=blocked_hosts)
        # Include response-derived indicators without duplicating URL-only heuristics.
        response_findings = _url_findings(target, response)
        known = {x["key"] for x in findings}
        findings.extend(x for x in response_findings if x["key"] not in known)
        cert = response.get("certificate") or {}
        summary = {"http_status": response["status"], "content_type": response["headers"].get("content-type", "unknown"),
                   "content_length": response.get("content_length"), "domain": host,
                   "domain_is_ip_address": _is_ip_address(host), "scheme": scheme,
                   "tls": ({"https": True, "certificate_validated": response["tls_verified"],
                            "certificate_subject": str(cert.get("subject", ""))[:400] or "unavailable",
                            "certificate_expires": cert.get("notAfter", "unavailable"),
                            "hostname_match": bool(response["tls_verified"]),
                            "tls_version": response.get("tls_version"), "cipher": response.get("tls_cipher")}
                           if scheme == "https" else {"https": False, "certificate_validated": False}),
                   "redirect_chain": response["redirects"], "response_truncated": response["truncated"],
                   "reputation": reputation, "engines": ["local URL heuristics"] + ([reputation["provider"]] if reputation["status"] not in ("not_configured", "skipped_consent") else []),
                   "checks": [{"check": "URL syntax and scheme", "status": "valid", "evidence": f"Normalized {scheme.upper()} URL using a standard port.", "source": "local parser"},
                              {"check": "Hostname and public DNS", "status": "publicly routable", "evidence": f"Resolved to a validated public address ({response['redirects'][0]['address']}).", "source": "system DNS + public IP policy"},
                              {"check": "HTTP response", "status": str(response["status"]), "evidence": f"Content-Type {response['headers'].get('content-type','unknown')}; response size bounded.", "source": "remote HTTP response"},
                              {"check": "Reputation", "status": reputation["status"], "evidence": reputation.get("detail", "Provider result recorded."), "source": reputation["provider"]}],
                   "limitations": ["No reputation provider match does not prove safety.", "Response content was not executed or persisted.", "Only a bounded GET and redirect chain were examined."]}
        update(85)
        return findings, summary, "completed"
    except ScanCancelled:
        raise
    except Exception as exc:
        findings.append(_finding("fetch-incomplete", "Remote fetch could not be completed", "informational", "high", "scan-limitation",
            target, f"Fetch stopped safely ({type(exc).__name__}).", "The scanner could not obtain a bounded public response.",
            "Remote metadata checks could not be completed.", "Review the URL and retry only if you are authorized to assess it."))
        return findings, {"reputation": reputation, "engines": ["local URL heuristics"],
                         "limitations": ["Remote fetch unavailable; findings are incomplete."]}, "partial"


def _website_result(scan_id, cancel_check, update):
    scan = db.session.get(SecurityScan, scan_id)
    if not scan.authorized:
        raise UnsafeTarget("Website scans require an authorization confirmation.")
    target = scan.target
    scan_config = json.loads(scan.config_json or "{}")
    blocked_hosts = scan_config.get("blocked_hosts", [])
    scan_mode = scan_config.get("scan_mode", "comprehensive")
    findings = []
    _, _, _, allowed_host = normalize_target(target)
    try:
        base = safe_fetch(target, cancel_check=cancel_check, allowed_host=allowed_host, blocked_hosts=blocked_hosts)
    except ScanCancelled:
        raise
    except Exception as exc:
        title = "TLS certificate validation failed" if isinstance(exc, ssl.SSLCertVerificationError) else "Website response could not be inspected"
        severity = "high" if isinstance(exc, ssl.SSLCertVerificationError) else "informational"
        findings.append(_finding("website-fetch-failed", title, severity, "high" if severity == "high" else "medium",
            "tls" if severity == "high" else "scan-limitation", target,
            f"No response was analyzed ({type(exc).__name__}); no insecure fallback request was made.",
            "The target did not pass public-host validation or a bounded, normally validated request.",
            "A failed check does not establish site safety; invalid TLS can expose users to impersonation.",
            "Correct DNS and network reachability; for TLS, install a trusted, unexpired certificate matching the hostname."))
        return findings, {"tls": {"https": target.startswith("https://"), "certificate_validated": False,
                    "certificate_subject": "unavailable", "certificate_expires": "unavailable", "hostname_match": False},
                    "engines": ["bounded HTTP checks"], "limitations": ["The site response could not be validated; header and cookie checks were skipped."]}, "partial"
    findings.extend(_header_findings(target, base))
    findings.extend(_url_findings(target, base))
    if any(hop.get("downgrade") for hop in base["redirects"]):
        findings.append(_finding("https-downgrade", "HTTPS redirect chain downgraded to HTTP", "high", "high", "transport", target,
            "A redirect starting at HTTPS led to an HTTP URL on the authorized hostname.", "Redirect downgrades can remove transport encryption.",
            "Traffic after the redirect can be observed or modified on path.", "Keep the entire redirect chain on HTTPS and enforce HSTS."))
    tls = {"https": urllib.parse.urlsplit(target).scheme == "https",
           "certificate_validated": bool(base["tls_verified"]), "certificate_subject": "unavailable",
           "certificate_expires": "unavailable", "hostname_match": bool(base["tls_verified"]),
           "tls_version": base.get("tls_version"), "cipher": base.get("tls_cipher")}
    cert = base.get("certificate") or {}
    if cert:
        tls["certificate_subject"] = str(cert.get("subject", ""))[:400]
        tls["certificate_expires"] = cert.get("notAfter", "unavailable")
    if tls["https"] and not tls["certificate_validated"]:
        findings.append(_finding("tls-validation", "TLS certificate validation did not complete", "high", "high", "tls", target,
            "The HTTPS response completed without verified certificate metadata.", "This scanner requires normal certificate-chain and hostname validation.",
            "Users may not be securely connected to the intended website.", "Use a valid, unexpired certificate whose names match the site and whose chain is trusted."))
    update(35)
    # Same-host, fixed low-impact GET probes only. Each URL is independently resolved and validated.
    probes = (("/.env", "/.git/HEAD", "/server-status", "/actuator/env", "/admin/")
              if scan_mode == "comprehensive" else ())
    exposed, admin_paths = [], []
    origin = urllib.parse.urlsplit(target)
    for index, path in enumerate(probes):
        if cancel_check():
            raise ScanCancelled()
        probe_url = urllib.parse.urlunsplit((origin.scheme, origin.netloc, path, "", ""))
        try:
            response = safe_fetch(probe_url, cancel_check=cancel_check, max_redirects=0, max_bytes=2048,
                                  allowed_host=allowed_host, blocked_hosts=blocked_hosts)
            if response["status"] == 200 and path in ("/.env", "/.git/HEAD", "/server-status", "/actuator/env"):
                exposed.append(f"{path} returned HTTP 200 ({response['headers'].get('content-type','unknown')}).")
            if response["status"] == 200 and path == "/admin/":
                admin_paths.append("/admin/ returned HTTP 200; an administrative interface may be publicly reachable.")
        except ScanCancelled:
            raise
        except Exception:
            pass
        update(35 + int((index + 1) / len(probes) * 50))
    if exposed:
        findings.append(_finding("sensitive-resource", "Potentially sensitive resource is publicly reachable", "high", "medium", "exposure", target,
            " ".join(exposed), "A small set of common sensitive paths returned HTTP 200; response bodies and secrets were not retained.",
            "Publicly exposed configuration or repository metadata may disclose secrets or source details.",
            "Remove the resource from the public document root and restrict access; rotate any exposed credentials."))
    if admin_paths:
        findings.append(_finding("admin-path", "Administrative path responded publicly", "low", "low", "exposure", target,
            " ".join(admin_paths), "The scanner only observed an HTTP status and did not authenticate or interact with the page.",
            "A publicly reachable administration page may attract unwanted access attempts; this is not proof of an access-control flaw.",
            "Confirm the route is intended to be public and enforce authentication and network access controls where appropriate."))
    if base["status"] >= 500:
        body_lower = _body_text(base).lower()[:12000]
        markers = [x for x in ("traceback", "stack trace", "exception in", "sql syntax", "debugger is active") if x in body_lower]
        if markers:
            findings.append(_finding("verbose-error", "Verbose server error details observed", "medium", "medium", "information-disclosure", target,
                "HTTP 5xx response contains a generic stack-trace/debug marker; response contents were not retained.",
                "Verbose errors can disclose implementation or dependency details.", "Implementation information can aid targeted attacks.",
                "Disable debug output in production and return generic error pages."))
    source_text = _body_text(base)
    if re.search(r"sourceMappingURL\s*=\s*[^\s*]+", source_text, re.I):
        findings.append(_finding("source-map-reference", "Client source map reference observed", "low", "medium", "information-disclosure", target,
            "The bounded root response contains a sourceMappingURL marker; the referenced map was not fetched.",
            "Published source maps may expose original client source and build paths.",
            "Source maps can make client implementation details easier to inspect; this does not demonstrate a server-side vulnerability.",
            "Confirm public source maps are intentional and do not contain secrets or sensitive source comments."))
    text = source_text.lower()
    if "index of /" in text[:10000]:
        findings.append(_finding("directory-listing", "Potential directory listing exposed", "medium", "medium", "exposure", target,
            "The root response contains a common directory-index marker.", "A directory listing may disclose files and application structure.",
            "Exposed files can reveal sensitive data.", "Disable directory indexing and restrict non-public files."))
    h = base["headers"]
    html_context = "text/html" in h.get("content-type", "").lower()
    header_items = [("content-security-policy", "Content-Security-Policy"),
                    ("strict-transport-security", "Strict-Transport-Security"),
                    ("x-content-type-options", "X-Content-Type-Options"),
                    ("referrer-policy", "Referrer-Policy"), ("permissions-policy", "Permissions-Policy")]
    if not html_context:
        header_items = [item for item in header_items if item[0] != "content-security-policy"]
    if urllib.parse.urlsplit(target).scheme != "https":
        header_items = [item for item in header_items if item[0] != "strict-transport-security"]
    header_checks = [{"check": label, "status": "present" if h.get(key) else "missing",
                      "evidence": (f"{label} response header was observed." if h.get(key) else f"{label} response header was not observed."),
                      "source": "initial HTTP response"}
                     for key, label in header_items]
    if html_context:
        header_checks.append({"check": "Framing protection", "status": "present" if ("frame-ancestors" in h.get("content-security-policy", "").lower() or h.get("x-frame-options", "").lower() in ("deny", "sameorigin")) else "missing",
                              "evidence": "CSP frame-ancestors or a compatible X-Frame-Options value was inspected.", "source": "initial HTTP response"})
    checks_run = ["public DNS and pinned HTTP request", "TLS certificate validation" if tls["https"] else "HTTP transport", "security headers and cookies", "redirect behavior", "bounded response indicators"]
    if scan_mode == "comprehensive":
        checks_run.append("five fixed same-host public-exposure paths")
    checks_not_assessed = ["XSS and injection: no payloads submitted; source code and authenticated workflows are not inspected.",
        "SQL injection, path traversal, and SSRF behavior: not actively tested to avoid changing target behavior.",
        "IDOR, access control, authentication, CSRF, and session lifecycle: not assessed without a dedicated authorized test account and application context.",
        "Upload handling and authorization-dependent resources: not assessed.",
        "Legacy TLS protocol negotiation: only the normally negotiated TLS version/cipher is observed; obsolete protocols are not actively probed."]
    details = {"scan_mode": scan_mode, "http_status": base["status"], "headers": {k: v for k, v in base["headers"].items() if k != "set-cookie"},
               "tls": tls, "redirect_chain": base["redirects"], "probe_paths": list(probes), "checks_run": checks_run,
               "checks_not_assessed": checks_not_assessed,
               "checks": [{"check": "HTTP status", "status": str(base["status"]), "evidence": f"HTTP {base['status']}", "source": "initial HTTP response"},
                          {"check": "TLS certificate chain and hostname", "status": "verified" if tls["certificate_validated"] else "not verified", "evidence": f"Certificate validation uses the system trust store and hostname verification; {base.get('tls_version') or 'TLS version unavailable'} / {base.get('tls_cipher') or 'cipher unavailable'}.", "source": "TLS handshake"},
                          *header_checks,
                          *[{"check": f"Cookie flags: {cookie.split('=',1)[0][:80]}",
                             "status": "missing attributes" if any(token not in cookie.lower() for token in ("; secure", "; httponly", "; samesite=")) else "present",
                             "evidence": "Cookie values were discarded; Secure, HttpOnly and SameSite attributes were inspected.", "source": "Set-Cookie response header"}
                            for cookie in base["headers"].get("set-cookie", "").splitlines()]],
               "engines": ["bounded HTTP checks", "response-header inspection", "TLS certificate validation" if tls["https"] else "HTTP transport check"],
               "limitations": ["Only the submitted origin" + (" and five fixed same-host paths were requested." if scan_mode == "comprehensive" else " was requested; path exposure checks were skipped for Quick Scan."),
                               "No crawling, exploit payloads, authentication tests, or destructive actions were performed.",
                               "Findings are indicators and do not prove the absence or presence of untested vulnerabilities."]}
    return findings, details, "completed"


def _risk(findings):
    # CNS rating is a transparent worst-finding rubric, not CVSS. Confidence is reported separately.
    worst = max((SEVERITY_POINTS.get(item["severity"], 0) for item in findings), default=0)
    score = worst
    level = "critical" if score == 100 else "high" if score >= 75 else "medium" if score >= 50 else "low" if score >= 25 else "informational"
    counts = {severity: sum(item["severity"] == severity for item in findings) for severity in SEVERITY_ORDER}
    return score, level, counts


def _set_progress(scan_id, value):
    row = db.session.get(SecurityScan, scan_id)
    if row is not None and not row.cancel_requested:
        row.progress = max(row.progress, min(95, int(value)))
        row.status = "running"
        if row.started_at is None:
            row.started_at = utcnow()
        db.session.commit()


def _is_cancelled(scan_id, deadline=None):
    if deadline is not None and time.monotonic() >= deadline:
        raise ScanTimedOut()
    with _cancel_lock:
        event = _cancellations.get(scan_id)
    if event and event.is_set():
        return True
    db.session.expire_all()
    row = db.session.get(SecurityScan, scan_id)
    return row is None or bool(row.cancel_requested)


def _run(app, scan_id, file_path=None):
    started = time.monotonic()
    with app.app_context():
        row = db.session.get(SecurityScan, scan_id)
        if row is None or row.status == "cancelled":
            _slots.release()
            return
        row.status = "running"
        row.started_at = utcnow()
        db.session.commit()
        scan_config = json.loads(row.config_json or "{}")
        timeout = max(1, int(app.config.get("SECURITY_SCAN_TIMEOUT_SECONDS", 30)))
        if row.scan_type == "file" and scan_config.get("upload_file_to_virustotal"):
            timeout = max(timeout, 75)
        deadline = started + timeout
        cancelled = lambda: _is_cancelled(scan_id, deadline)
        stored_file_path = None
        try:
            if row.scan_type == "file":
                findings, summary, status = _file_result(file_path, scan_id, cancelled)
            elif row.scan_type == "url":
                findings, summary, status = _url_result(scan_id, cancelled, lambda p: _set_progress(scan_id, p))
            else:
                findings, summary, status = _website_result(scan_id, cancelled, lambda p: _set_progress(scan_id, p))
            if _is_cancelled(scan_id, deadline):
                raise ScanCancelled()
            score, level, counts = _risk(findings)
            row = db.session.get(SecurityScan, scan_id)
            if row.scan_type == "file" and scan_config.get("store_shared_file_on_clean"):
                scanner_result = summary.get("scanner", {})
                if status == "completed" and scanner_result.get("status") == "clean":
                    storage_root = Path(app.config["INSTANCE_DIR"]) / "shared-files"
                    storage_root.mkdir(parents=True, exist_ok=True)
                    storage_key = secrets.token_hex(24)
                    stored_file_path = storage_root / storage_key
                    shutil.copyfile(file_path, stored_file_path)
                    try:
                        os.chmod(stored_file_path, 0o600)
                    except OSError:
                        pass
                    shared = SharedFile(owner_id=row.user_id, storage_key=storage_key,
                        filename=row.target, size_bytes=int(scan_config["size_bytes"]),
                        sha256=scan_config["sha256"], mime_type=scan_config.get("mime_type", "application/octet-stream"),
                        scan_status="clean")
                    db.session.add(shared)
                    db.session.flush()
                    summary["shared_file_id"] = shared.id
                    summary["file_storage"] = "Stored privately after a completed clean provider scan."
                else:
                    summary["file_storage"] = "Not stored or shared because the multi-engine scan was not completed cleanly."
            for item in findings:
                db.session.add(SecurityFinding(scan_id=scan_id, **item))
            row.summary_json = json.dumps({**summary, "severity_counts": counts,
                "risk_method": "Risk score is the highest severity weight among findings: Critical 100, High 75, Medium 50, Low 25, Informational 0. Confidence is separate and does not change severity."}, ensure_ascii=True)
            row.risk_score, row.risk_level = score, level
            row.status = status
            row.progress = 100
            row.duration_ms = int((time.monotonic() - started) * 1000)
            row.completed_at = utcnow()
            db.session.commit()
            if summary.get("shared_file_id"):
                log_event("file_uploaded", "info", user=db.session.get(User, row.user_id),
                          detail=f"file_id={summary['shared_file_id']} scan={row.id} scan_status=clean provider=virustotal")
            actor = db.session.get(User, row.user_id)
            log_event("security_scan_" + status, "critical" if level in ("critical", "high") else "info",
                      user=actor, detail=f"scan_id={row.id} type={row.scan_type} status={status} risk={level} finding_count={len(findings)}")
        except ScanCancelled:
            row = db.session.get(SecurityScan, scan_id)
            if row:
                row.status, row.progress, row.completed_at = "cancelled", 0, utcnow()
                row.error = "Cancelled by the user."
                row.duration_ms = int((time.monotonic() - started) * 1000)
                db.session.commit()
                actor = db.session.get(User, row.user_id)
                log_event("security_scan_cancelled", "warning", user=actor, detail=f"scan_id={row.id} type={row.scan_type}")
        except ScanTimedOut:
            row = db.session.get(SecurityScan, scan_id)
            if row:
                row.status, row.progress, row.completed_at = "partial", 100, utcnow()
                row.error = "The scan exceeded its configured total time limit; remaining checks were skipped."
                row.duration_ms = int((time.monotonic() - started) * 1000)
                row.summary_json = json.dumps({"severity_counts": {s: 0 for s in SEVERITY_ORDER},
                    "engines": [], "limitations": ["Scan timed out before all checks completed; no clean conclusion is available."],
                    "risk_method": "No overall score is assigned to an incomplete scan."})
                row.risk_score, row.risk_level = None, "unknown"
                db.session.add(SecurityFinding(scan_id=row.id, key="scan-timeout", title="Scan timed out before completion",
                    severity="informational", confidence="high", category="scan-limitation", affected=row.target,
                    evidence="The configured scan deadline was reached; remaining checks were stopped.",
                    explanation="Partial results cannot establish target safety.", impact="Additional checks were not completed.",
                    remediation="Retry with a responsive public target or increase SECURITY_SCAN_TIMEOUT_SECONDS within the bounded deployment policy.",
                    source="job scheduler", verification="incomplete"))
                db.session.commit()
                actor = db.session.get(User, row.user_id)
                log_event("security_scan_partial", "warning", user=actor, detail=f"scan_id={row.id} type={row.scan_type} reason=timeout")
        except Exception as exc:
            db.session.rollback()
            if stored_file_path is not None:
                try:
                    stored_file_path.unlink(missing_ok=True)
                except OSError:
                    pass
            row = db.session.get(SecurityScan, scan_id)
            if row:
                row.status, row.completed_at = "failed", utcnow()
                row.error = f"Scan failed ({type(exc).__name__})."
                row.duration_ms = int((time.monotonic() - started) * 1000)
                row.summary_json = json.dumps({"severity_counts": {s: 0 for s in SEVERITY_ORDER},
                    "engines": [], "limitations": ["Scan failed; no safety conclusion is available."],
                    "risk_method": "Worst-finding rubric; no score is available for a failed scan."})
                db.session.commit()
                actor = db.session.get(User, row.user_id)
                log_event("security_scan_failed", "warning", user=actor,
                          detail=f"scan_id={row.id} type={row.scan_type} error={type(exc).__name__}")
        finally:
            if file_path:
                try:
                    Path(file_path).unlink(missing_ok=True)
                except OSError:
                    pass
            db.session.remove()
            with _cancel_lock:
                _cancellations.pop(scan_id, None)
    _slots.release()


def submit_scan(app, scan_id, file_path=None):
    global _pool
    if not _slots.acquire(blocking=False):
        return False
    with _pool_lock:
        if _pool is None:
            from concurrent.futures import ThreadPoolExecutor
            _pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="cns-scan")
        with _cancel_lock:
            _cancellations[scan_id] = threading.Event()
        _pool.submit(_run, app, scan_id, file_path)
    return True


def request_cancel(scan_id):
    with _cancel_lock:
        event = _cancellations.get(scan_id)
    if event:
        event.set()


def safe_scan_file(upload, filename, limit, temp_dir):
    import hashlib
    import tempfile
    temp_dir = Path(temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=True)
    fd, path = tempfile.mkstemp(prefix="security-scan-", suffix=".bin", dir=temp_dir)
    digest, size = hashlib.sha256(), 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = upload.stream.read(64 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    raise ValueError("File exceeds the configured upload size limit.")
                digest.update(chunk)
                out.write(chunk)
        with open(path, "rb") as sample_file:
            header = sample_file.read(32)
        if header.startswith(b"%PDF-"): mime = "application/pdf"
        elif header.startswith(b"\x89PNG\r\n\x1a\n"): mime = "image/png"
        elif header.startswith(b"\xff\xd8\xff"): mime = "image/jpeg"
        elif header.startswith((b"GIF87a", b"GIF89a")): mime = "image/gif"
        elif header.startswith(b"7z\xbc\xaf\x27\x1c"): mime = "application/x-7z-compressed"
        elif header.startswith(b"PK\x03\x04"):
            ext = Path(filename).suffix.lower()
            mime = {".docx":"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    ".xlsx":"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    ".pptx":"application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    ".docm":"application/vnd.ms-word.document.macroEnabled.12",
                    ".xlsm":"application/vnd.ms-excel.sheet.macroEnabled.12",
                    ".pptm":"application/vnd.ms-powerpoint.presentation.macroEnabled.12"}.get(ext, "application/zip")
        else: mime = mimetypes.guess_type(filename)[0] or "text/plain"
        return path, size, digest.hexdigest(), mime
    except Exception:
        Path(path).unlink(missing_ok=True)
        raise

