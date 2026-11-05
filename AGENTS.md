# Salvage Cloud AI agent instructions

Use this file to work safely within the Salvage Cloud codebase. It describes the project layout, required verification, security boundaries, and change workflow. It is not user-facing product documentation.

## Project map

- `crates/backend-core`: account tenancy, authentication, Telegram transports, bot provisioning and selection, transfers, encrypted session persistence, and workspace stores.
- `crates/server`: Axum HTTP/SSE API, middleware, static assets, previews, public shares, and production configuration.
- `crates/web`: Leptos browser application compiled to WebAssembly.
- `crates/crypto-worker`: dedicated Rust/WASM Worker for TDENC2 encryption, decryption, vaults, recovery, OPFS, and continuation journals.
- `crates/tdenc2`: frozen TDENC2/TDVLT2/TDREC2 implementation and native compatibility journeys.
- `crates/protocol`: shared native/WASM DTOs and server events.
- `tests/e2e`: browser, HTTP/storage, restart, and controlled-fixture journeys.
- `docs`: architecture, deployment, bot, privacy, sharing, and threat-model documentation.
- `deploy`: Caddy configuration, hardened systemd units, installer, and encrypted backup/restore utilities.

## Required workflow

1. Read the relevant code and tests before editing. Preserve the existing architecture and E2E-only testing policy.
2. Add an application-boundary regression journey before fixing a behavior bug. Exercise real browser journeys, native child-process/HTTP/storage lifecycles, or controlled external-service fixtures.
3. Run `node scripts/check-test-policy.mjs` before handing off testing changes. Do not add unit-test suites, Vitest, Testing Library, or inline Rust test modules.
4. Before completion, run:

   ```sh
   cargo fmt --all -- --check
   npm test
   npm run check
   ```

   `npm test` runs the same E2E suite as `npm run test:e2e`. Formatting, Clippy, native/WASM compilation, dependency, localization, security, and bundle checks are separate from behavioral tests.
5. Report exactly what was run. Never describe skipped, fixture-only, or unavailable acceptance checks as live production verification.

## Security invariants

- Derive tenancy from authenticated server-side state, never browser-supplied account IDs, workspace paths, or owner IDs.
- Preserve account-scoped databases, late-request invalidation, encrypted Telegram sessions, Origin/CSRF enforcement, and secret redaction.
- Keep TDENC2 keys, passphrases, and plaintext cryptographic processing in the browser Worker. Do not publish plaintext before final authenticated verification or weaken frozen-format compatibility.
- Bot tokens and MTProto sessions are encrypted backend credentials. Bots publish only to channels/groups with administrator posting rights, never to Saved Messages, and never to bypass Telegram limits.
- Preserve encrypted resume state, including the selected `bot_id`, so a retry cannot silently change publication identity.
- Do not commit `.env`, production databases, Telegram sessions, recovery material, local data directories, build output, or credentials. Do not print secrets in logs, traces, screenshots, test output, or commit messages.
- Keep Caddy access and reverse-proxy request/error logs disabled because URLs and headers can contain capabilities or CSRF tokens.

## Change boundaries

- Keep Saved Messages as the root drive and Telegram channels as storage folders. Automatic rollover must affect only the active channel; existing files remain mapped to their original channels.
- Preserve plain and TDENC2 resume, verified Range downloads, public-share revocation/expiry, and encrypted backup/restore behavior.
- Do not enable the Telegram fixture outside development. Production uses Grammers and the official Bot API behind Caddy HTTPS with one persistent writer.
- Do not change production HTTPS, account isolation, feature availability, or release protections without updating the corresponding E2E coverage and documentation.
- Update `README.md`, `TESTING.md`, and relevant `docs/` pages when behavior or deployment changes.

## Git and delivery

- Keep changes focused and inspect the complete diff before committing. Do not include local configuration or generated `target/` and `dist/` artifacts.
- Do not push, publish releases, rotate signing keys, or perform production mutations unless the repository owner explicitly authorizes the specific action.
