# Production deployment

## Supported topology

Salvage Cloud runs as **one hardened Axum systemd service behind Caddy**, with one private persistent data directory:

- `salvage-cloud.service` listens only on `127.0.0.1:3000` as UID/GID `salvage`;
- `salvage-caddy.service` exposes ports 80/443 and proxies to that loopback address;
- `/var/lib/salvage-cloud` is the only application-writable persistent path;
- `/opt/salvage-cloud` contains root-owned release binaries and optimized WASM assets;
- `/etc/salvage-cloud/environment` contains runtime secrets with mode `0600`.

SQLite session/workspace state is single-writer. **Do not run a second application instance against the same data directory.** No Docker daemon or container runtime participates in the request path.

## Build

```sh
npm ci
npm run build:release
cargo build --locked --release -p salvage-server
```

The release pipeline produces optimized browser assets and a native server without `e2e-fixture`. Current optimized assets are approximately 2.5 MB for the app and 528 KB for the encryption worker, rather than development builds tens of megabytes larger.

## Configure

1. Point the public DNS hostname at this server and allow inbound TCP 80/443. Cloudflare HTTP proxying is supported.
2. Install Caddy 2.10.2 at `/usr/local/bin/caddy` from a verified official distribution.
3. Create private production settings:

   ```sh
   cp .env.production.example .env.production
   chmod 600 .env.production
   ```

4. Set:
   - `DOMAIN` and the identical HTTPS origin in `SALVAGE_PUBLIC_ORIGIN`;
   - a new random `SALVAGE_SESSION_KEY` from `openssl rand -hex 32`;
   - server-owned `TELEGRAM_API_ID` and `TELEGRAM_API_HASH` from my.telegram.org.

Keep production settings, Telegram login codes/passwords, session files, recovery material, and backup passphrases out of source control, screenshots, tickets, and chat. Changing `SALVAGE_SESSION_KEY` without a reviewed migration makes existing encrypted Telegram sessions unreadable.

## Cloudflare and HTTPS

For `safe.salvage.wtf`, Caddy obtained a Let's Encrypt certificate through Cloudflare using HTTP-01. The proxy configuration:

- preserves ACME challenge requests for renewals;
- redirects direct/plain HTTP to HTTPS;
- accepts Cloudflare-origin HTTP only when `X-Forwarded-Proto: https` identifies an already-secure client connection;
- also serves the origin certificate directly on HTTPS 443, supporting **Full (strict)** mode;
- streams SSE without proxy buffering and limits request bodies to 9 MB, above the backend's exact 8 MiB chunk ceiling.

Set Cloudflare SSL/TLS to **Full (strict)** after confirming origin issuance, and enable **Always Use HTTPS**. Do not expose port 3000 publicly.

**Caddy access logs and reverse-proxy request/error logs are intentionally discarded.** Public share tokens occur in `/s/{token}` URLs, and Caddy's error records can include CSRF headers. Application and non-request Caddy operational logs remain available through journald. Single-upstream health gating is disabled so one interrupted request cannot cause a `fail_duration` outage; monitor `/api/health` externally instead.

## Install or upgrade

```sh
sudo deploy/install.sh
```

The installer validates configuration without printing secrets, installs root-owned release files, preserves the existing data directory, installs hardened systemd units, validates Caddy, and starts/reloads both services. It is safe to rerun for upgrades after rebuilding.

Useful checks:

```sh
systemctl status salvage-cloud salvage-caddy
curl --fail https://DOMAIN/api/health
journalctl -u salvage-cloud -n 100 --no-pager
journalctl -u salvage-caddy -n 100 --no-pager
```

Both services handle graceful shutdown. Compose is not used. The application handles SIGINT/SIGTERM and systemd allows 45 seconds to stop accepting requests and finish in-flight work.

## Encrypted backup and restore

Maintenance stops the single application writer for a consistent offline snapshot. This causes a short outage. The scripts restart both services and wait for local HTTPS health before returning.

```sh
export SALVAGE_BACKUP_PASSWORD='use-a-secret-manager-not-shell-history'
sudo deploy/backup.sh /private/salvage-backups
```

Backups are AES-256-CBC encrypted with OpenSSL PBKDF2 and 600,000 iterations. The directory is mode `0700` and archives are mode `0600`. Keep the password separately; without it the backup is unrecoverable.

Restore requires an explicit confirmation flag. The archive is decrypted and gzip-verified **before** the existing data directory is replaced:

```sh
export SALVAGE_BACKUP_PASSWORD='the-same-backup-password'
sudo deploy/restore.sh --yes /private/salvage-backups/salvage-cloud-TIMESTAMP.tar.gz.enc
```

`SALVAGE_DATA_DIR` can point at an isolated directory for restore drills. The included drill was exercised with dummy data: backup encryption, replacement, decryption, content recovery, and app/proxy recovery all passed. Perform an additional drill with real production data before relying on recovery, including Telegram/web sessions, account isolation, staged transfers, and public shares.

## Security controls and acceptance

The application retains CSP, frame, content-type, cache, exact-Origin, CSRF, Secure/HttpOnly/SameSite cookie, and account-isolation protections. Caddy adds HSTS and public HTTPS. Authentication adds per-phone request throttling, verification-failure invalidation, and a bounded pending-login pool.

Live acceptance has verified a real account restore, current Saved Messages listing, a complete 107,646-byte progressive-photo download, and a synthetic upload → metadata → byte-identical download → delete journey.

Release acceptance still requires the operational checks appropriate to the deployment:

- Telegram DC-migration/CDN edge behavior, large transfers, flood waits, and restart recovery;
- external HTTPS and renewal verification;
- real-data backup/restore and incident-response drills;
- independent TDENC2 cryptographic review;
- Firefox/Safari and OPFS-unsupported-browser acceptance or a documented supported-browser policy;
- disk, login, transfer, and service-health monitoring.
