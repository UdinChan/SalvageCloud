# Preview and plain-file sharing

## Inline previews

Plain files can be prepared through the normal verified download pipeline and rendered inline by the browser. The current allowlist is:

- UTF-8 `text/plain` up to 1 MiB in the UI;
- PNG, JPEG, GIF, and WebP images;
- PDF in a same-origin iframe;
- audio and video formats supported by the browser, with HTTP Range.

HTML, SVG, JavaScript, XML, unknown types, and unsupported formats are attachment-only. Responses use `X-Content-Type-Options: nosniff`, private/no-store caching, and `Referrer-Policy: no-referrer`. Only inline PDF responses replace the normal deny-framing policy with `SAMEORIGIN` and `frame-ancestors 'self'`.

Protected/TDENC2 files cannot be previewed through this path. Their encrypted sharing and browser-decryption design is a separate milestone.

## Public snapshots

A share is a **verified snapshot captured when the owner creates it**. Later edits to the Telegram message do not change that snapshot. Creating a share performs one account-authorized staged download; anonymous visitors never invoke Telegram or create additional staging files.

- Tokens contain 32 random bytes in URL-safe form and are shown only once.
- The service database stores only the token's SHA-256 hash, owner account ID, file ID, verified transfer ID, display metadata, and expiry/revocation state.
- The default expiry is 24 hours. Owners can choose 1–168 hours or **Never expires**; the API also accepts a precise seconds override for short-lived links and expiry testing. Non-expiring links remain public until revoked.
- Existing-link management exposes metadata and revocation, not the original token.
- Anyone with the complete link can read the snapshot until expiry or revocation; no recipient login is required.
- Unknown, expired, revoked, and malformed tokens return the same not-found response.
- Snapshots can survive owner logout and backend restart because they do not depend on restoring the owner's Telegram transport.
- Revocation stops new and subsequent Range requests and removes staging best-effort. It cannot retract a response already streaming or copies the recipient already downloaded.

Share tokens are capabilities. Do not place them in analytics, logs, referrer headers, fixtures, or browser persistence. Production access logs must redact `/s/` capability paths.
