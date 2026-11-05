#![forbid(unsafe_code)]
//! Reusable TDENC2 envelope, TDVLT2 vault, and TDREC2 recovery primitives.
//!
//! This crate performs no filesystem or network I/O. Envelope writers use fixed 1 MiB
//! plaintext chunks; record APIs keep memory bounded by one chunk plus its tag. The
//! two-pass decryptor publishes to a writer only after whole-file verification.

mod error;
mod kdf;

pub mod header;
pub mod metadata;
pub mod recovery;
pub mod stream;
pub mod vault;

pub use error::{Error, Result};
pub use header::{Credential, Header, KeySlot, SlotKind, UnlockedHeader};
pub use kdf::Argon2Params;
pub use metadata::ProtectedMetadata;
pub use stream::{
    ChunkEncryptor, DecryptedEnvelope, EncryptionSession, FinishedEncryption, SessionRandomness,
    SlotRandomness, TransferSummary,
};
pub use vault::{ContainerRandomness, VaultPayload, VaultProfile};

use std::io::{Read, Write};

/// Creates a fresh session and encrypts exactly `total_plaintext_len` bytes.
pub fn encrypt_reader<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    total_plaintext_len: u64,
    metadata: Option<ProtectedMetadata>,
    credentials: &[Credential],
) -> Result<TransferSummary> {
    EncryptionSession::new(total_plaintext_len, metadata, credentials)?
        .encrypt_reader(reader, writer)
}

/// Reads and authenticates only the header, leaving the reader at the first content record.
pub fn decrypt_header<R: Read>(
    reader: &mut R,
    credentials: &[Credential],
) -> Result<UnlockedHeader> {
    Header::read_from(reader)?.unlock(credentials)
}

pub use stream::decrypt_reader;
