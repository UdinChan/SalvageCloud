use crate::error::Result;
use crate::kdf::Argon2Params;
use crate::vault::{
    ContainerKind, ContainerRandomness, VaultPayload, open_container, seal_container,
};

pub const RECOVERY_MAGIC: &[u8; 6] = b"TDREC2";
pub const MAX_RECOVERY_PAYLOAD_BYTES: usize = crate::vault::MAX_RECOVERY_PAYLOAD_BYTES;

pub fn seal_recovery(payload: &VaultPayload, passphrase: &[u8]) -> Result<Vec<u8>> {
    seal_recovery_with_options(payload, passphrase, Argon2Params::WRITER_DEFAULT)
}

pub fn seal_recovery_with_options(
    payload: &VaultPayload,
    passphrase: &[u8],
    argon2: Argon2Params,
) -> Result<Vec<u8>> {
    seal_container(
        ContainerKind::Recovery,
        payload,
        passphrase,
        argon2,
        ContainerRandomness::generate()?,
    )
}

pub fn seal_recovery_with_randomness(
    payload: &VaultPayload,
    passphrase: &[u8],
    argon2: Argon2Params,
    randomness: ContainerRandomness,
) -> Result<Vec<u8>> {
    seal_container(
        ContainerKind::Recovery,
        payload,
        passphrase,
        argon2,
        randomness,
    )
}

pub fn open_recovery(container: &[u8], passphrase: &[u8]) -> Result<VaultPayload> {
    open_container(ContainerKind::Recovery, container, passphrase)
}
