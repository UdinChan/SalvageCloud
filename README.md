# Salvage Cloud

Salvage Cloud is a Telegram-backed cloud drive written in Rust. The hosted backend uses Axum, and the browser interface uses Leptos compiled to WebAssembly. No React or Tauri runtime is required.

## Features

- Phone/code, cloud-password, and QR login with secure HttpOnly web sessions.
- Saved Messages as the drive root and Telegram channels as storage folders.
- Automatic channel creation, discovery/synchronization, active-channel selection, and rollover at a configurable file-message limit.
- Per-account encrypted bot tokens and sessions for administrator-authorized channel uploads, including automatic provisioning and least-loaded automatic selection.
- Durable chunked uploads with prefix-hash resume, verified downloads, Range support, and restart recovery.
- Inline text, image, PDF, audio, and video previews, plus expiring, revocable, and non-expiring plain-file public shares.
- TDENC2/TDVLT2/TDREC2 encryption with browser Worker processing, OPFS-backed decryption, and recovery export/import.
- Account-scoped SQLite workspaces, encrypted Telegram session persistence, Origin/CSRF enforcement, and account-scoped server-sent events.
- Responsive Rust/WASM UI with file and populated-channel deletion controls.
- Caddy HTTPS reverse proxy and hardened systemd services for production deployment.

## Architecture

- `crates/backend-core`: accounts, Telegram transports, bot provisioning, transfers, encrypted session storage, and workspace persistence.
- `crates/server`: Axum HTTP/SSE API, authentication middleware, static assets, previews, and public shares.
- `crates/web`: Leptos browser application.
- `crates/crypto-worker`: dedicated Rust/WASM Worker for TDENC2 encryption, decryption, vaults, recovery, and continuation journals.
- `crates/tdenc2`: frozen encryption-format implementation and compatibility journeys.
- `crates/protocol`: shared native/WASM data types.

## Requirements

- Rust 1.99.1 with `wasm32-unknown-unknown`
- Trunk 0.22.1
- Node.js and npm
- Playwright Chromium for browser tests
- Caddy 2.10.2 for production HTTPS

Install development dependencies:

```sh
rustup target add wasm32-unknown-unknown
cargo install trunk --version 0.22.1 --locked
npm ci
npx playwright install chromium
```

## Development

Copy `.env.example` to `.env`, generate a random `SALVAGE_SESSION_KEY`, and provide server-owned Telegram API credentials for live mode. Never commit `.env`, production data, or credentials.

The controlled Telegram fixture is available only with the explicit development feature:

```sh
SALVAGE_BIND=127.0.0.1:3000 \
SALVAGE_PUBLIC_ORIGIN=http://127.0.0.1:3000 \
SALVAGE_COOKIE_SECURE=false \
SALVAGE_SESSION_KEY=$(openssl rand -hex 32) \
SALVAGE_TELEGRAM_TRANSPORT=fixture \
SALVAGE_WEB_DIST=./dist \
SALVAGE_DATA_DIR=./data \
cargo run -p salvage-server --features e2e-fixture
```

Fixture-only credentials are login code `12345`; phones ending in `2222` also require `salvage-test-password`. These synthetic values cannot access Telegram.

## Verification

```sh
npm test
npm run check
```

`npm test` builds the WASM UI, runs TDENC2 and encrypted Telegram-session child-process journeys, starts the real Axum server with temporary SQLite storage, and runs browser/HTTP/restart journeys. Only Telegram is controlled by fixtures. See [TESTING.md](TESTING.md) for coverage and acceptance boundaries.

## Production

The supported topology is one hardened systemd application service behind Caddy HTTPS with one persistent writer. No container runtime is required in the request path.

See:

- `docs/deployment.md` for release builds, Cloudflare/HTTPS setup, secrets, upgrades, and encrypted backup/restore procedures.
- `docs/bots.md` for BotFather setup, automatic provisioning, administrator requirements, rotation, active channels, and QR approval.
- `deploy/install.sh` to install or update the release after building.

Never enable the Telegram fixture in production. Live DC-migration/CDN behavior, large-transfer/flood-wait behavior, Firefox/Safari coverage, real-data recovery drills, and independent TDENC2 cryptographic review remain separate acceptance requirements.

## License

Salvage Cloud is licensed under the **GNU General Public License v3.0 only**. See [LICENSE](LICENSE).
