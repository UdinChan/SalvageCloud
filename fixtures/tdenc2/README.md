# TDENC2 compatibility fixtures

These public deterministic compatibility fixtures originate from the Telegram Drive
v3.9.8 test-vector set, with a later current-envelope compatibility input containing
`sync_path`.

Provenance is recorded in `manifest.json`: Telegram Drive tag `v3.9.8` and source
commit `10f470617fd24d955acfda00350d535e1551be48`. They contain no personal Telegram
sessions, private keys, user files, or production credentials. The passphrases and
deterministic key material are deliberately public test inputs.

The Salvage Cloud native child-process journey checks deterministic envelope bytes,
continuation, decryption, recovery, and corruption refusal. This evidence is not a
live Telegram acceptance run or an independent cryptographic review.
