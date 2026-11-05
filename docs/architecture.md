# Architecture

Salvage Cloud is a same-origin Rust web application:

```text
Leptos/WASM browser ── HTTPS/SSE ── Axum ── account-scoped backend services ── Grammers ── Telegram
        │                                  │
        ├─ encrypted vault/OPFS            ├─ service SQLite (accounts/web sessions)
        └─ TDENC2 Worker                   └─ per-account SQLite/staging/session envelopes
```

The server derives an internal account ID from the authenticated Telegram self-user and web-session record. `AccountContext` owns the transport, workspace store, generation guard, cancellation/event boundary, and account-specific state. Browser IDs are never authorization inputs.

Saved Messages represents the root drive, channels represent folders, and Telegram media messages represent files. Telegram is authoritative; SQLite is an account-scoped inventory cache.

Web sessions are random opaque values stored as SHA-256 hashes. Session cookies are HttpOnly and SameSite=Strict; production also requires Secure. Mutations require the configured Origin and a per-session CSRF header. SSE channels belong to one account context.

Serialized Telegram sessions are sealed with XChaCha20-Poly1305 before any file write. The envelope has a key-version field for a future reviewed key-management implementation. A host able to use the configured decryption key can still recover sessions; this is not protection against a compromised host.

The dedicated TDENC2 Worker keeps encryption keys and plaintext processing in the browser. Plain files are processed by the hosted backend. OPFS-backed decryption, encrypted continuation journals, vaults, and recovery are implemented in the Worker.

See `docs/deployment.md` for the current production topology and remaining acceptance requirements.
