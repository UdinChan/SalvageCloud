# Privacy

Salvage Cloud is being designed as a hosted service, not a local-only application. A deployment operator processes Telegram authentication and ordinary uploaded/downloaded file content. Telegram receives account, destination, timing, and file metadata according to its own service behavior.

Web sessions use opaque HttpOnly cookies. The service stores account records, hashed web-session tokens, account-scoped catalog/settings/transfer data, and encrypted Telegram session envelopes on its persistent volume. Authentication attempts and CSRF values must not be logged.

The intended encrypted-file mode keeps TDENC2 vault keys, passphrases, and plaintext cryptographic processing in the browser Worker. Telegram and the hosted backend still observe ciphertext size and transfer metadata. Protected filenames must not enter server catalogs, search indexes, logs, or staging paths.

Browser IndexedDB/OPFS data can be evicted and is not a backup. Users must retain verified recovery bundles. Standard browser downloads and file pickers do not provide arbitrary local-folder synchronization.

Synthetic Telegram fixtures are used only for development and E2E tests. Production retention, deletion, backup, incident-response, and user-consent interfaces must be reviewed and validated for each deployment before accepting additional accounts.
