# Keep CNS cryptographic keys across Render Free deploys

Render Free discards service-local files on restarts and deploys. In persistent-key mode, CNS keeps the original master key in the Render environment and stores wrapped account signing keys plus the encrypted transport private key in Supabase PostgreSQL.

## 1. Select the matching key backup

Use the original `keys/` directory that belongs to the Supabase database's existing users. It must contain `aes_master.key`, `elgamal_private.hex` when protected messages already exist, and `users/<id>.ed25519.wrapped` for every account. Never commit or send these files in chat. The migration tool checks each private key against the public key in Supabase and stops without writing keys on any mismatch.

## 2. Point a local shell at the same Supabase database

Use the same Supabase `DATABASE_URL` configured in Render. It can be supplied in the local, gitignored `.env` file or in your terminal environment. Keep the connection string private.

From the repository root, run a validation first:

```bash
python3 scripts/migrate_keys_to_supabase.py --key-dir instance/backups/<matching-backup>/keys
```

If validation succeeds, apply the migration:

```bash
python3 scripts/migrate_keys_to_supabase.py --key-dir instance/backups/<matching-backup>/keys --apply
```

The script inserts missing key records but refuses to replace any different key already in the database. Re-running after a successful migration is safe.

## 3. Put the original master key in Render

Convert the original `aes_master.key` bytes to lowercase hexadecimal and add the result as the Render environment variable `CNS_MASTER_KEY`. For example, in PowerShell from the repo root:

```powershell
$masterHex = [Convert]::ToHexString([IO.File]::ReadAllBytes('instance\backups\<matching-backup>\keys\aes_master.key')).ToLowerInvariant()
Set-Clipboard -Value $masterHex
Remove-Variable masterHex
```

Paste the clipboard value directly into **Render → your service → Environment → Add Environment Variable** with key `CNS_MASTER_KEY`. Do not put it in Git, a browser, or chat. Keep `DATABASE_URL` configured. Save and deploy.

## 4. Confirm health

After deploy, open `https://<your-service>.onrender.com/api/health` while signed in to the app and check that `key_check.state` is `HEALTHY`, `key_check.key_pairings_ok` is `true`, and all database signing-key pairs were checked. New registrations will store their wrapped signing key in Supabase automatically.

If migration validation reports a public-key mismatch or missing account key, stop. That backup does not match the deployed accounts; do not set `CNS_MASTER_KEY` or generate replacement keys until the correct backup is found.
