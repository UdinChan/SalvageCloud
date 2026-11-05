# Threat model

## Assets

Telegram session auth keys, API hashes, login codes, phone-code hashes, cloud passwords, QR material, phone numbers, proxy credentials, web-session tokens, CSRF secrets, file contents/metadata, TDENC2 vault keys/passphrases/DEKs, recovery bundles, and account-scoped transfer state are sensitive.

## Boundaries

- The browser is an XSS/compromise boundary. Use restrictive CSP, no broad `unsafe-eval`, no sensitive persistent tokens in JavaScript-readable storage, and same-origin API access.
- The hosted backend mediates ordinary Telegram traffic and plaintext files. Users must consent to this trust change from a local-first client.
- TDENC2 secrets belong in the browser Worker. The backend must not receive vault passphrases or plaintext encrypted-file content.
- SQLite workspaces, staging files, account registries, caches, SSE streams, and Telegram runners are tenant boundaries.
- Telegram sessions are account authority. Encryption at rest does not protect against a host that can decrypt them.

## Required controls

Authenticate every request from server-side web-session state; derive object ownership on the server. Bind pre-auth attempts, rotate sessions, enforce expiry, Origin and CSRF checks, strict production HTTPS, secret redaction, login/range/body/time limits, per-account/global quotas, and private atomic staging. Invalidate late work on logout/session replacement.

Do not run multiple service replicas against SQLite session/workspace state without a separate fencing design. Control SSRF, decompression, transcoding processes, public-share capabilities, Telegram flood waits, disk exhaustion, and cache eviction as those features land.

Never put credentials, raw tokens, protected filenames, file contents, or recovery material in logs, traces, URLs, analytics, fixtures, WASM configuration, or public errors. CORS is not authorization.

## Release gates

Hostile two-account E2E journeys, encrypted-storage inspection, TDENC2 compatibility/corruption journeys, dependency/configuration checks, backup/restore and incident-response procedures are required before production. General availability also requires an independently commissioned TDENC2 cryptographic review.
