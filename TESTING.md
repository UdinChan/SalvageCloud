# End-to-end testing

## Commands

```sh
npm ci
npx playwright install chromium
npm test
npm run check
```

`npm test` builds the Leptos/WASM application, runs the TDENC2 and encrypted Telegram-session native child-process journeys, starts the real Axum server with temporary SQLite storage, and runs Playwright browser, HTTP/storage, and process-restart journeys. The server is built with `e2e-fixture`; only Telegram is controlled. The fixture has no Telegram network access and uses synthetic identities.

## Current journeys

- health, invalid code, phone/code and cloud-password authentication;
- QR login issuance/polling and normal web-session restoration;
- encrypted per-account bot tokens, authorized channel publication, Saved Messages/non-admin/cross-account denial, and token removal;
- automatic bot provisioning, least-loaded automatic selection, and active-channel rollover at a small fixture part limit;
- automatic channel creation, active-channel bot selection, individual file deletion, and populated-channel deletion with synchronization;
- per-phone login-code throttling, verification-failure invalidation, pending-login bounds, and unaffected neighboring-account login;
- encrypted Telegram session catch-up with deferred writes, batched export, and peer/update-state restoration through real encrypted files;
- web-session restoration and logout;
- root file listing and two-account object isolation;
- cross-account rename/delete denial, CSRF and Origin enforcement;
- encrypted Telegram session envelope presence and absence of plaintext web-session tokens in persisted files;
- chunked uploads, prefix-hash resume, verified full/Range downloads, and cross-account transfer denial;
- actual WASM upload/download/history, interrupted multi-chunk upload resume after reload, and responsive navigation;
- compiled-WASM login, folder/file/search and responsive navigation, SPA routes with successful HTTP status, and live Trunk asset rebuilds that refresh the bootstrap CSP without a server restart;
- real backend restart with preserved web session and staged upload state;
- deterministic TDENC2 envelope bytes and continuation, authenticated decryption, vault recovery, wrong-key rejection, and tested truncation/reordering/bit-flip/trailing-byte corruption without plaintext publication;
- public share snapshots with anonymous full/Range reads, actual expiry, non-expiring links, owner revocation, cross-account denial, token-hash-only persistence, active-content attachment safety, same-origin PDF framing, nullable-expiry migration, and availability after owner logout/backend restart;
- actual WASM TDENC2 passphrase/vault upload and OPFS decryption, frozen golden-envelope decryption, recovery export/import, interrupted continuation, changed-source fresh restart, wrong-passphrase/corruption refusal without OPFS artifacts, two-account vault isolation, and active-job cancellation on account switch;
- actual WASM text/raster-image previews, one-time share-link creation/revocation, and protected-file preview/share disablement.

## Required boundaries for later milestones

- interrupted/resumed transfers, restart recovery, quotas, changed sources, and large files;
- hostile multi-tenant delayed responses, concurrent logins, logout/revocation, and late-work rejection;
- TDENC2 public golden vectors exercised through visible browser Worker upload/download/recovery journeys, including corruption/truncation refusal;
- secrets absent from responses, logs, URLs, browser persistence, and unauthorized staging;

## Live Telegram acceptance driver

`crates/backend-core/test-support/live_driver.rs` is an opt-in real-Telegram journey, excluded from the default suite. With an existing encrypted account session, it verifies account identity, current root listing, metadata lookup, and a full temporary-file download. `SALVAGE_LIVE_FILE_ID=latest` selects the current first file; an explicit `scope:message-id` selects another. `SALVAGE_LIVE_WRITE_TEST=1` additionally uploads a tiny synthetic document, downloads and compares it, and deletes the test message.

Required environment: `SALVAGE_SESSION_KEY`, `TELEGRAM_API_ID`, `TELEGRAM_API_HASH`, `SALVAGE_LIVE_ACCOUNT_DIR`, `SALVAGE_LIVE_TELEGRAM_USER_ID`, and `SALVAGE_LIVE_FILE_ID`. Optional `SALVAGE_LIVE_TEST_FILE_NAME` and `SALVAGE_LIVE_TEST_MIME` verify filename/MIME preservation (for example, an MP4). Run with `cargo run -p salvage-backend-core --features native-e2e --bin salvage-live-e2e-driver`. Never print the session key, Telegram credentials, account identifiers, file names, or file contents in reports. Live write mode is limited to its own synthetic test message.

## Unrun acceptance

Telegram DC-migration/CDN edge behavior, real Telegram part expiry/flood waits, production HTTPS renewal, and horizontal scaling are not established by fixture journeys. The TDENC2 format requires an independently commissioned cryptographic review before general availability. Report these as unrun until actually exercised.
