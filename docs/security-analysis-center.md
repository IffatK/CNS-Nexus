# Malware & Website Security Analysis Center

## Setup

Install Python requirements (ReportLab is used for PDF export). On Ubuntu, local malware scanning also needs an updated ClamAV installation:

```bash
sudo apt install clamav clamav-freshclam
sudo freshclam
sudo systemctl enable --now clamav-freshclam
```

For faster repeat uploads, install and run the persistent scanner daemon: `sudo apt install clamav-daemon && sudo systemctl enable --now clamav-daemon`. When `clamdscan` is present and reachable, uploads use its already-loaded signatures; if it is unavailable or errors, the application falls back to `clamscan`. Set `CLAMDSCAN_PATH=` in `.env` to disable daemon attempts.

If `clamav-freshclam` is already updating signatures, do not start a second updater. The app marks a scan incomplete if ClamAV is missing, unavailable, times out, or cannot finish; it never converts those outcomes to clean.

Render's Free web service has an ephemeral filesystem, 512 MB RAM, and spins down when idle. That is below ClamAV's 3 GiB recommended RAM, so installing the package in a free Render build does not make local ClamAV reliable. The file scan pages offer an optional VirusTotal multi-engine submission instead. The scan runs as a background job and returns a partial result with the provider report link if VirusTotal is still processing after the bounded wait. Free Render cold starts cannot be eliminated without an always-on instance.

On the Secure File Sharing page, users may separately opt in to VirusTotal upload when configured. The file remains unshareable until the background scan completes cleanly; pending, failed, suspicious, or infected outcomes do not store or share it. VirusTotal checks are bounded and spaced to respect its public API limits; a completed clean result is stored privately and the report links back to the file-sharing page to configure recipients. For durable files on Render, set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` (and optionally `SUPABASE_STORAGE_BUCKET`); the app creates a private bucket when needed. Without those settings, file bytes use local disk and can disappear after a Render Free restart or redeploy.

The following settings are optional:

- `SECURITY_SCAN_TIMEOUT_SECONDS=30` bounds malware subprocess time and is checked between network operations. Network operations use short socket timeouts and byte/redirect limits; a system DNS resolver call cannot be interrupted, so the total network-scan deadline is best effort.
- `GOOGLE_SAFE_BROWSING_API_KEY` enables URL reputation checks. The user must opt in for each URL scan; the URL is then disclosed to Google Safe Browsing.
- `VIRUSTOTAL_API_KEY` enables VirusTotal file-hash lookups and optional multi-engine file uploads. Hash lookup sends only SHA-256 after consent. Full sample upload has a separate per-scan consent checkbox; VirusTotal says submitted samples are added to its dataset and accessible to the community. Do not upload confidential, personal, or sensitive files. Public API availability and rate limits apply.

Do not commit real provider credentials. Missing keys do not prevent startup or local scanning.

## Scope and behavior

The analysis center stores scans and findings in the application database. A small in-process executor runs at most two scans concurrently and allows up to four queued/running jobs. A process restart marks unfinished jobs failed so they do not appear to run forever. This is suitable for the bounded educational workload; a multi-worker production deployment should replace it with a durable queue.

URL and website fetches permit HTTP/HTTPS on ports 80/443 only, resolve and validate all addresses as globally routable, connect to a validated address directly, and revalidate every redirect. Redirects stay on the submitted hostname; a new hostname requires a separate explicitly authorized scan. Quick Website Scan requests only the submitted origin (plus same-host redirects); Comprehensive Scan adds five fixed same-host GET checks (`/.env`, `/.git/HEAD`, `/server-status`, `/actuator/env`, `/admin/`). Neither mode crawls, executes JavaScript, authenticates, brute-forces, or sends exploit payloads. Response bytes are capped, cookies are never persisted, and only cookie names/flag gaps may appear in findings. TLS findings rely on normal trust-chain and hostname verification; failed TLS validation is not treated as healthy. Legacy TLS protocol negotiation is not actively probed.

Remote unauthenticated scans cannot reliably verify XSS, SQL injection, IDOR/broken access control, authenticated CSRF/session weaknesses, path traversal, upload authorization, or application-specific SSRF behavior. These are explicitly listed as not assessed in the persisted report; the scanner does not run active exploit payloads. Source-map references are observed only in the bounded response body; referenced files are not fetched. DNS resolver stalls cannot be interrupted by the best-effort total deadline.

The rating is a transparent worst-finding rubric, not CVSS: Critical=100, High=75, Medium=50, Low=25, Informational=0; the highest severity weight is the overall score. Confidence is separate and does not modify severity. No findings and a clean ClamAV result are not guarantees of safety.

Reports are generated from persisted scan records. History, detail, JSON, CSV, and PDF access are restricted to the scan owner. Exports are audit-logged. CSV output neutralizes spreadsheet formula prefixes. The scanner does not store uploaded bytes after a scan. Existing `security_findings` tables receive additive remediation/verification-step columns at startup after the standard instance backup.

## API contract

- `POST /security-center/scan/website` accepts `url`, required `authorized=on`, and optional `scan_mode=quick|comprehensive`; returns `202` with the persisted scan ID and status.
- `POST /security-center/scan/url` accepts `url` and optional per-scan `share_reputation=on` consent.
- `POST /security-center/scan/file` accepts multipart `file` and optional `share_file_hash=on` consent.
- `GET /security-center/api/scans/<id>` returns the owner-scoped persisted status, progress, risk, and result links.
- `POST /security-center/api/scans/<id>/cancel` requests cancellation (CSRF required).
- `GET /security-center/<id>` displays persisted findings and recommendations; `/report.json`, `/report.csv`, and `/report.pdf` export the same owner-scoped scan record.

Mutating routes require authentication and CSRF validation. The background executor accepts a maximum of four queued/running jobs globally and runs two concurrently.

## Migrations and tests

`db.create_all()` creates the additive `security_scans` and `security_findings` tables on startup. Existing user, message, and file rows are not modified. Tests should mock DNS/HTTP/reputation services or use isolated fixtures; never use an unauthorized public target.
