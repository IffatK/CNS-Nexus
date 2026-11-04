# Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Modified ciphertext/metadata at rest or in transit | GCM tag + AAD + Ed25519 over canonical envelope; verify-before-decrypt | host administrator can alter the app/database or hold server keys |
| Forged sender | Ed25519 per-user key; public key in DB | attacker with DB **and** key dir can forge |
| Cross-user access (IDOR) | participant check in one service function; 404 for missing and forbidden alike; denial logged | app vulnerabilities or privileged host access remain in scope |
| SQL injection | SQLAlchemy parameterised queries, WTForms validation, int path converters | not a substitute for ongoing security review |
| CSRF | Flask-WTF tokens on all POSTs, SameSite=Lax, POST-only logout | none known |
| Session theft/replay | HttpOnly, SameSite=Lax, Secure under HTTPS, server-tracked session id, 30 min lifetime, revocation | insecure only if an operator deliberately disables HTTPS on the isolated lab network |
| Credential guessing | scrypt, throttling per user+IP and per IP | distributed guessing; throttling can lock a victim username (DoS) from one IP only |
| User enumeration | identical login error and timing-equalised hash check | registration reveals taken usernames |
| XSS | Jinja autoescape, CSP limits scripts and connections to self and permits styles/fonts only from the explicit Google Fonts origins, no inline script, JS uses `textContent` | Google Fonts metadata and font requests are visible to Google |
| Secret leakage | keys 0600 outside Git, `.env` ignored, log content restricted | server operator sees everything |
| Network eavesdropping | HTTPS protects network traffic in the documented setup | Ubuntu terminates TLS and can inspect application data; the plaintext relay mode is intentionally visible to the server |
| Server compromise | none | master key + wrapped keys on same host: full break |
Out of scope: DoS, physical access, hypervisor compromise, multi-node deployment.
