# Architecture and three-VM layout

```text
Windows user browser ─┐
                      ├─ HTTPS :5000 ─ Ubuntu Flask + SQLite + key store + manual relay
Kali user browser ────┘                         └─ admin-only /attacker console
```

The host-only example addresses are Windows `192.168.56.1`, Ubuntu `192.168.56.102`, Kali `192.168.56.101`. Ubuntu hosts every backend component; Windows and Kali are user clients. Only an admin should use `/attacker`, preferably from the Ubuntu VM as the designated attacker operator. Bind the service only on the isolated host-only network in a real lab.

## Application structure

- `app.py` builds one Flask app, enables Flask-WTF CSRF, registers routes, adds browser security headers, and refuses HTTPS-required startup without readable TLS files.
- `routes/` handles HTTP/authz; `services/` contains crypto, message relay, file type checks, scanner invocation, logging, and health checks.
- `instance/cns_lab.db` stores users, encrypted messages, relay envelopes, scan metadata, private file metadata, audit events, per-user notifications, settings, login attempts, and session records.
- `instance/keys/` holds a random 32-byte AES master key and per-user Ed25519 private keys wrapped with AES-GCM. Files are created exclusively and restricted to owner read/write on POSIX. A missing key for an existing database is a hard error.
- `instance/shared-files/` stores only accepted files under random names; uploaded content is never placed in the static/public directory.
- `instance/scanner-tmp/` is a private temporary scan location. Upload bytes are deleted in a `finally` block after scanning.

## Message envelope and relay

The signed envelope binds message UUID, sender/recipient IDs, timestamp, algorithm, nonce, and AES-GCM ciphertext. Ed25519 verifies the canonical envelope before decryption. Invalid signatures or failed AEAD authentication return no plaintext. The unchanged plaintext relay preserves the original sender signature and is labelled `UNPROTECTED RELAY`; an edited relay re-encrypts with a fresh nonce while keeping the original signature, so verification fails and plaintext is withheld. The attacker does not receive a signing operation for the sender's identity. Queue transitions are claimed atomically to prevent duplicate forwarding; every action is audited.

This is not end-to-end encryption: Ubuntu owns the master key and user signing keys. Browser transport encryption is a teaching simulation and also terminates at Ubuntu.

## Sessions, CSRF, and HTTPS

Browser forms use Flask-WTF tokens; JSON state changes use the same token in `X-CSRFToken`, with one fresh-token retry after an expired token. CSRF remains enabled. `Referrer-Policy: strict-origin-when-cross-origin` preserves Flask-WTF's same-origin HTTPS referer check while limiting cross-origin referrer detail. Sessions are HttpOnly, SameSite=Lax, and Secure when HTTPS is required. A random server-side session identifier is tracked and checked on requests; revocation takes effect on the next request. Password changes increment the session epoch and revoke sessions.

The attacker console is a standalone template rather than one extending the regular page base. It must load `static/js/app.js` before `static/js/attacker.js`; the shared script provides `window.cnsPostJSON`, token refresh, and the `X-CSRFToken` header required by relay actions. A regression test protects this dependency order.

Set `REQUIRE_HTTPS=1`, `SESSION_COOKIE_SECURE=1`, and TLS cert/key paths in Ubuntu `.env`. The provided script generates an isolated-lab self-signed cert for Ubuntu's host-only IP; trust its certificate on Windows and Kali, and never copy its private key. Use the same HTTPS hostname/IP and port for form loads and submissions.

## Scanning and file integrity

ClamAV is invoked using an argument list with `shell=False`, a 120-second default timeout, and a two-scan semaphore. `clamscan` loads the signature database into a fresh engine on each invocation, so cold scans on small VMs may be slower than subsequent operations; the limit is configurable with `CLAMSCAN_TIMEOUT`. Only a completed clean result permits a file share. Missing engine, scanner errors, timeouts, busy status, and detections cannot be reported as clean. Type checks verify a small set of file signatures; this is not a complete content-disarm system. Files retain a SHA-256 digest, checked again on download; mismatch blocks delivery and creates a critical event.

## Additive startup schema updates

`db.create_all()` creates missing tables only. `create_app()` detects supported additions (`messages.protection`, `intercepted_messages.envelope_json`), writes a dated SQLite/key backup first, then applies additive `ALTER TABLE` statements. Existing user data and key files are never intentionally replaced. `scripts/init_db.py` makes a backup before initialization and checks for unsupported missing columns. Backups are written under the instance backup area; protect them as sensitive because they contain keys.

When `CNS_MASTER_KEY` is configured, the master key is loaded from that environment secret, per-user wrapped Ed25519 keys are loaded from `user_signing_keys`, and the ElGamal transport key is stored encrypted in `application_key_material`. Use `scripts/migrate_keys_to_supabase.py` to validate and migrate the matching original key files before enabling this mode. Never run with a newly generated master key against existing public keys or protected messages.

The dashboard's authenticated `/api/dashboard/metrics` endpoint aggregates only rows the signed-in account is authorized to see (administrators see lab-wide totals). It returns bounded time buckets and status counts; message contents, IP addresses, keys, and credentials are excluded. `/api/diagnostics` performs live checks and returns safe status strings. Chart event severities reflect the existing three-value model (`info`, `warning`, `critical`); no low/high levels are inferred.

## Useful routes

User pages: `/dashboard`, `/compose`, `/inbox`, `/sent`, `/messages/<id>`, `/account`, `/notifications`, `/virus-scanner`, `/files`, `/events`, `/settings`.
Admin operator page: `/attacker`. Health endpoints: `/api/health`, `/api/diagnostics`; chart data: `/api/dashboard/metrics`; CSV reports: `/events.csv` and `/virus-scanner/reports.csv`.
