use std::io;

/// Fail-closed errors produced while parsing, authenticating, or transforming data.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid format magic")]
    InvalidMagic,
    #[error("unsupported format version {0}")]
    UnsupportedVersion(u16),
    #[error("unsupported cipher suite {0}")]
    UnsupportedCipherSuite(u16),
    #[error("invalid complete header length")]
    InvalidHeaderLength,
    #[error("complete header exceeds 65536 bytes")]
    HeaderTooLarge,
    #[error("invalid key-slot table length")]
    InvalidSlotTableLength,
    #[error("key-slot count must be between 1 and 8")]
    InvalidSlotCount,
    #[error("duplicate key-slot ID {0}")]
    DuplicateSlotId(u8),
    #[error("unsupported key-slot kind {0}")]
    InvalidSlotKind(u8),
    #[error("key-slot kind and KDF are incompatible")]
    InvalidSlotKdf,
    #[error("HKDF key slots must have zero Argon2 parameter fields")]
    InvalidHkdfFields,
    #[error("Argon2 parameters are outside the TDENC2 reader policy")]
    InvalidKdfParameters,
    #[error("Argon2 key derivation failed")]
    KdfFailed,
    #[error("chunk size is outside the TDENC2 reader policy")]
    InvalidChunkSize,
    #[error("writer chunk size must be exactly 1048576 bytes")]
    InvalidWriterChunkSize,
    #[error("invalid encrypted metadata length")]
    InvalidMetadataLength,
    #[error("protected metadata exceeds the available header space")]
    MetadataTooLarge,
    #[error("protected metadata is invalid: {0}")]
    InvalidMetadata(String),
    #[error("no credential is available for key-slot {0}")]
    MissingCredential(u8),
    #[error("authentication failed during {0}")]
    AuthenticationFailed(&'static str),
    #[error("key slots do not contain the same data-encryption key")]
    InconsistentDataKeys,
    #[error("plaintext length changed from {expected} to {actual} bytes")]
    PlaintextLengthMismatch { expected: u64, actual: u64 },
    #[error("plaintext chunk has an invalid length for its position")]
    InvalidChunkLength,
    #[error("plaintext has already been finalized")]
    AlreadyFinalized,
    #[error("plaintext is incomplete")]
    IncompletePlaintext,
    #[error("truncated {0}")]
    Truncated(&'static str),
    #[error("trailing bytes after the final record")]
    TrailingBytes,
    #[error("ciphertext length is {actual}, expected {expected}")]
    CiphertextLengthMismatch { expected: u64, actual: u64 },
    #[error("length calculation overflowed")]
    LengthOverflow,
    #[error("content chunk count exceeds u32::MAX")]
    ChunkCountOverflow,
    #[error("invalid final record")]
    InvalidFinalRecord,
    #[error("whole-file SHA-256 digest does not match")]
    DigestMismatch,
    #[error("invalid vault payload: {0}")]
    InvalidVaultPayload(&'static str),
    #[error("vault profile ID must contain 1 through 128 UTF-8 bytes")]
    InvalidProfileId,
    #[error("duplicate vault profile ID")]
    DuplicateProfileId,
    #[error("vault profiles are not sorted by ID")]
    UnsortedProfiles,
    #[error("a vault can contain at most 64 profiles")]
    TooManyProfiles,
    #[error("recovery plaintext payload exceeds 1 MiB")]
    RecoveryPayloadTooLarge,
    #[error("system randomness is unavailable: {0}")]
    Randomness(String),
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn random_bytes(output: &mut [u8]) -> Result<()> {
    getrandom::fill(output).map_err(|error| Error::Randomness(error.to_string()))
}
