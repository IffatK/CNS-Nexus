# CNS Security Lab

An educational Flask lab for secure messaging, signature verification, an authorized manual relay, file scanning and sharing, and account security.

> **For learning and demonstrations only.** Run the three-VM lab on an isolated VirtualBox host-only network. This project is not production security software: the server controls message keys, and browser transport encryption is educational rather than end-to-end encryption. See [Security limitations](docs/limitations.md).

## Contents

- [What’s included](#whats-included)
- [Lab network](#lab-network)
- [Run on Ubuntu](#run-on-ubuntu)
- [Open the portals](#open-the-portals)
- [Database and deployment](#database-and-deployment)
- [Tests and documentation](#tests-and-documentation)

## What’s included

- AES-GCM message storage and Ed25519 signature verification
- Admin-only manual message relay for authorized lab demonstrations
- ClamAV file scanning, private file sharing, and SHA-256 integrity checks
- Account session management, security events, and dashboard charts
- Responsive client and attacker interfaces

## Lab network

| Machine | Role | Example host-only IP |
| --- | --- | --- |
| Windows | Client portal | `192.168.56.1` |
| Ubuntu | Flask app, database and keys, admin console | `192.168.56.102` |
| Kali | Client portal | `192.168.56.101` |

Ubuntu owns the server-side keys. Windows and Kali are clients. Keep all three VMs on the same host-only network; do not expose the Flask development server through a bridged or public interface.

## Run on Ubuntu

### 1. Install system packages

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip openssl clamav clamav-freshclam
```

Let Ubuntu’s `clamav-freshclam` service update the virus definitions. Check it with:

```bash
systemctl status clamav-freshclam
```

Avoid running `sudo freshclam` while that service is active; both processes use the same database lock.

### 2. Install Python dependencies

Run these commands from the project directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

If the project is inside a VirtualBox shared folder and creating `.venv` there fails, keep the environment on Ubuntu’s local filesystem instead:

```bash
python3 -m venv ~/.venvs/cns-security-lab
source ~/.venvs/cns-security-lab/bin/activate
pip install -r requirements.txt
```

### 3. Initialize the app

For a normal local checkout:

```bash
python3 scripts/init_db.py
```

If your project is in a VirtualBox shared folder, keep the database, keys, TLS files, and uploaded files on Ubuntu’s local filesystem. For a **new** instance, initialize it with a local data directory:

```bash
mkdir -p ~/cns-security-lab-data
python3 scripts/init_db.py --instance-dir "$HOME/cns-security-lab-data"
```

Then set the same absolute path in the project’s `.env` before starting the app:

```dotenv
CNS_INSTANCE_DIR=/home/your-ubuntu-username/cns-security-lab-data
```

Replace the example path with your Ubuntu username. For an existing installation, do not switch instance directories or initialize a replacement database until you have backed up and moved the existing database and keys. See [VirtualBox data move instructions](docs/three-vm-operations.md).

`init_db.py` leaves an existing `.env` and master key in place. It backs up existing local data before supported schema updates. Never regenerate keys for a populated database.

### 4. Configure trusted lab HTTPS

The app requires HTTPS by default. If you do not already have a trusted certificate for this lab, generate one once on Ubuntu:

```bash
python3 scripts/generate_lab_tls.py --ip 192.168.56.102
```

If `CNS_INSTANCE_DIR` is outside the project, generate the certificate there instead. For example:

```bash
python3 scripts/generate_lab_tls.py --ip 192.168.56.102 --output "$HOME/cns-security-lab-data/tls"
```

The script will not overwrite existing TLS files. In Ubuntu’s `.env`, check these settings:

```dotenv
REQUIRE_HTTPS=1
SESSION_COOKIE_SECURE=1
TLS_CERT_FILE=instance/tls/lab.crt
TLS_KEY_FILE=instance/tls/lab.key
APP_HOST=0.0.0.0
APP_PORT=5000
```

If `CNS_INSTANCE_DIR` points somewhere else, set `TLS_CERT_FILE` and `TLS_KEY_FILE` to the matching absolute paths there (for example `/home/your-ubuntu-username/cns-security-lab-data/tls/lab.crt` and `.../lab.key`). Keep the private `lab.key` on Ubuntu. Copy only `lab.crt` to the client VMs and trust it there.

On Windows, in elevated PowerShell:

```powershell
certutil -addstore -f Root lab.crt
```

On Kali:

```bash
sudo install -m 0644 lab.crt /usr/local/share/ca-certificates/cns-lab.crt
sudo update-ca-certificates
```

Use the certificate only in this isolated lab. If your organization already provides a lab CA, use its certificate instead.

### 5. Start Flask

```bash
source .venv/bin/activate
python3 app.py
```

If you created the virtual environment under `~/.venvs`, activate that path instead. Keep the app running in the terminal while using the lab.

## Open the portals

Use the same HTTPS origin from all lab VMs:

- Client portal: `https://192.168.56.102:5000/`
- Admin attacker console: `https://192.168.56.102:5000/attacker`
- Virus scanner: `https://192.168.56.102:5000/virus-scanner`
- File sharing: `https://192.168.56.102:5000/files`
- Security events: `https://192.168.56.102:5000/events`

Register separate accounts for the admin and client roles. `ADMIN_USERNAMES` in `.env` lists usernames assigned the admin role at registration. Client accounts cannot access the attacker console or address admin accounts as message or file recipients.

Useful pages include `/dashboard`, `/compose`, `/inbox`, `/sent`, `/notifications`, and `/events.csv`. The API endpoints `/api/dashboard/metrics` and `/api/diagnostics` require authentication.

## Database and deployment

SQLite is the default for the isolated lab. Supabase PostgreSQL is also supported through `DATABASE_URL`. For Render Free, set `CNS_MASTER_KEY` to the hex form of the original 32-byte master key. In this mode, wrapped account signing keys and the encrypted transport private key are persisted in Supabase PostgreSQL, while the master key remains a Render environment secret. Run `scripts/migrate_keys_to_supabase.py` against the deployment database with the matching original `instance/keys` directory before enabling this mode; the script validates key/public-key pairings and refuses mismatches. For persistent file sharing, configure `SUPABASE_URL` and `SUPABASE_SECRET_KEY` (or legacy `SUPABASE_SERVICE_ROLE_KEY`); the app stores file bytes in a private `cns-shared-files` Supabase Storage bucket (override with `SUPABASE_STORAGE_BUCKET`). Without these Storage settings, files use local disk and can disappear after a Render restart or redeploy. Keep master, secret, and service-role keys private; never place them in frontend code. A database URL change does not migrate SQLite data automatically. Back up the database and original key directory together.

For a free public demo setup using an Ubuntu VM, Supabase, Gunicorn, and Caddy, follow the [free deployment guide](docs/free-deployment-oracle-supabase.md). The public deployment guide has additional limits and backup requirements. Do not treat the educational app as a service for real confidential data.

For persistent signing keys on Render Free with Supabase, follow the [key migration guide](docs/render-supabase-key-migration.md) before enabling `CNS_MASTER_KEY`.

Keep `.env`, database credentials, backups, keys, and `instance/` out of Git; the repository’s `.gitignore` covers local secrets and generated files. The deployment guide explains the Supabase connection setup.

## Tests and documentation

Run tests from the project directory:

```bash
source .venv/bin/activate
python3 -m pytest
```

Check service health against the lab certificate:

```bash
python3 scripts/health_check.py https://192.168.56.102:5000 --ca-cert instance/tls/lab.crt
```

More detail:

- [Architecture](docs/architecture.md)
- [Security limitations](docs/limitations.md)
- [Threat model](docs/threat_model.md)
- [Three-VM operations](docs/three-vm-operations.md)
- [Testing](docs/testing.md)
- [Transport demonstration](docs/transport-demo.md)
- [Free deployment](docs/free-deployment-oracle-supabase.md)
