# Free deployment: Oracle Cloud VM + Supabase

This setup keeps the app's database in Supabase and its signing keys and shared
files on a persistent Ubuntu VM. The app's current file and key storage is
local, so do not deploy it to a host with an ephemeral filesystem.

## Free-tier limits

- Oracle currently lists Always Free VM capacity, but signup may require a
  payment card, the selected home region can run out of free capacity, and
  Oracle may reclaim compute it considers idle. Keep a separate backup of the
  VM's `/var/lib/cns-security-lab` directory.
- Supabase Free currently includes a 500 MB database and 1 GB file storage;
  the app stores files locally, so only its relational database quota applies.
  Free projects can pause after a week with too little database activity.
- This is a low-traffic demo deployment, not a highly available or managed
  production service. Supabase Free does not include downloadable database
  backups. Export PostgreSQL data and back up the VM keys/files regularly.

## 1. Create the services

1. Create an Oracle Cloud Free Tier account and launch an Ubuntu 24.04 VM using
   only an Always Free eligible shape in your home region. A small Ampere A1 VM
   is preferable to the 1 GB micro instance when running ClamAV.
2. Assign a public IPv4 address. In the VCN security list and Ubuntu firewall,
   allow TCP ports 80 and 443; limit SSH port 22 to your own IP where possible.
3. Create a Supabase Free project. In **Connect**, copy the PostgreSQL
   connection string, preferably the Session Pooler connection string. Keep it
   private.
4. Point a domain you control (or a free dynamic DNS hostname) to the VM's
   public IP. Caddy uses the hostname to obtain and renew a trusted HTTPS
   certificate.

## 2. Install the app on the VM

SSH into Ubuntu and install the runtime packages:

```sh
sudo apt update
sudo apt install -y python3-venv python3-dev build-essential libpq-dev clamav clamav-freshclam
sudo freshclam
sudo systemctl enable --now clamav-freshclam
```

Put the project at `/opt/cns-security-lab` (clone your Git repository or copy
the project files), then create a dedicated service account and persistent
storage directory:

```sh
sudo useradd --system --create-home --home-dir /opt/cns-security-lab --shell /usr/sbin/nologin cnsapp
sudo mkdir -p /var/lib/cns-security-lab
sudo chown -R cnsapp:cnsapp /opt/cns-security-lab /var/lib/cns-security-lab
sudo -u cnsapp python3 -m venv /opt/cns-security-lab/.venv
sudo -u cnsapp /opt/cns-security-lab/.venv/bin/pip install -r /opt/cns-security-lab/requirements.txt
```

Create `/opt/cns-security-lab/.env` and replace every example value:

```dotenv
SECRET_KEY=replace-with-a-long-random-secret
ADMIN_USERNAMES=your-admin-login
DATABASE_URL=postgresql://USER:PASSWORD@HOST:PORT/postgres?sslmode=require
CNS_INSTANCE_DIR=/var/lib/cns-security-lab
SESSION_COOKIE_SECURE=1
REQUIRE_HTTPS=0
TRUST_PROXY=1
CLAMSCAN_PATH=clamscan
CLAMSCAN_TIMEOUT=120
```

Generate the secret with `python3 -c 'import secrets; print(secrets.token_hex(32))'`.
Use the PostgreSQL URI exactly as Supabase provides it and URL-encode special
characters in its password. Set permissions so only the service account can
read it:

```sh
sudo chown cnsapp:cnsapp /opt/cns-security-lab/.env
sudo chmod 600 /opt/cns-security-lab/.env
```

Initialize the database schema and master key once:

```sh
sudo -u cnsapp sh -c 'cd /opt/cns-security-lab && .venv/bin/python scripts/init_db.py'
```

Do not regenerate or discard `/var/lib/cns-security-lab/keys`; existing
messages rely on the same master and user keys.

## 3. Run Gunicorn with systemd

Create `/etc/systemd/system/cns-security-lab.service`:

```ini
[Unit]
Description=CNS Security Lab Flask application
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cnsapp
Group=cnsapp
WorkingDirectory=/opt/cns-security-lab
EnvironmentFile=/opt/cns-security-lab/.env
ExecStart=/opt/cns-security-lab/.venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8000 --access-logfile - --error-logfile - "app:create_app()"
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/var/lib/cns-security-lab

[Install]
WantedBy=multi-user.target
```

Then start it:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now cns-security-lab
sudo systemctl status cns-security-lab
```

Gunicorn listens only on loopback. Do not expose port 8000 publicly.

## 4. Put Caddy in front for HTTPS

Install Caddy using its official Ubuntu package instructions. Create
`/etc/caddy/Caddyfile`, replacing the hostname with the DNS name pointed at
your VM:

```caddyfile
lab.example.net {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8000
}
```

Validate and reload:

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

Open `https://lab.example.net`. Caddy needs public DNS to point to the VM and
inbound ports 80 and 443 open to obtain a browser-trusted certificate. The app
trusts one proxy only when `TRUST_PROXY=1`; keep Gunicorn bound to loopback so
untrusted clients cannot forge proxy headers.

## 5. Verify and maintain

- Register an account whose username matches `ADMIN_USERNAMES` for the admin
  console; use different usernames for regular accounts.
- Check service logs with `sudo journalctl -u cns-security-lab -f`.
- Back up `/var/lib/cns-security-lab` and use `pg_dump` for the Supabase
  database. Restore both together; database records alone are not sufficient
  to recover encryption keys and privately stored files.
- For each code update, deploy the new source, install updated requirements,
  and restart with `sudo systemctl restart cns-security-lab`.
