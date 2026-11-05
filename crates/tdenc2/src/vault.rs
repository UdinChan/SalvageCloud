use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result, random_bytes};
use crate::kdf::{Argon2Params, open, seal};

pub const VAULT_MAGIC: &[u8; 6] = b"TDVLT2";
pub const VAULT_PAYLOAD_MAGIC: &[u8; 6] = b"TDVPL2";
pub const CONTAINER_HEADER_BYTES: usize = 64;
pub const MAX_PROFILES: usize = 64;
pub const MAX_PROFILE_ID_BYTES: usize = 128;
pub const MAX_RECOVERY_PAYLOAD_BYTES: usize = 1_048_576;
pub const MAX_VAULT_PAYLOAD_BYTES: usize = 48 + MAX_PROFILES * (2 + MAX_PROFILE_ID_BYTES + 32);
const VAULT_AAD: &[u8] = b"telegram-drive:persistent-vault:v2";
pub(crate) const RECOVERY_AAD: &[u8] = b"telegram-drive:recovery-bundle:v2";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultProfile {
    pub id: String,
    pub key: [u8; 32],
}

impl VaultProfile {
    pub fn new(id: impl Into<String>, key: [u8; 32]) -> Result<Self> {
        let profile = Self { id: id.into(), key };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<()> {
        let length = self.id.len();
        if length == 0 || length > MAX_PROFILE_ID_BYTES {
            return Err(Error::InvalidProfileId);
        }
        Ok(())
    }
}

impl std::fmt::Debug for VaultProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultProfile")
            .field("id", &self.id)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Canonical binary vault payload shared by persistent vaults and recovery bundles.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultPayload {
    pub created_at: i64,
    pub master_key: [u8; 32],
    pub profiles: Vec<VaultProfile>,
}

impl VaultPayload {
    pub fn new(
        created_at: i64,
        master_key: [u8; 32],
        mut profiles: Vec<VaultProfile>,
    ) -> Result<Self> {
        profiles.sort_by(|left, right| left.id.as_bytes().cmp(right.id.as_bytes()));
        let payload = Self {
            created_at,
            master_key,
            profiles,
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let profiles_len = self
            .profiles
            .iter()
            .try_fold(0_usize, |total, profile| {
                total.checked_add(2 + profile.id.len() + 32)
            })
            .ok_or(Error::LengthOverflow)?;
        let length = 48_usize
            .checked_add(profiles_len)
            .ok_or(Error::LengthOverflow)?;
        let mut output = Vec::with_capacity(length);
        output.extend_from_slice(VAULT_PAYLOAD_MAGIC);
        output.extend_from_slice(&self.created_at.to_le_bytes());
        output.extend_from_slice(&self.master_key);
        output.extend_from_slice(&(self.profiles.len() as u16).to_le_bytes());
        for profile in &self.profiles {
            output.extend_from_slice(&(profile.id.len() as u16).to_le_bytes());
            output.extend_from_slice(profile.id.as_bytes());
            output.extend_from_slice(&profile.key);
        }
        Ok(output)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 48 || &bytes[..6] != VAULT_PAYLOAD_MAGIC {
            return Err(Error::InvalidVaultPayload("invalid header"));
        }
        let created_at = i64::from_le_bytes(bytes[6..14].try_into().expect("fixed range"));
        let master_key = bytes[14..46].try_into().expect("fixed range");
        let profile_count = u16::from_le_bytes([bytes[46], bytes[47]]) as usize;
        if profile_count > MAX_PROFILES {
            return Err(Error::TooManyProfiles);
        }
        let mut offset = 48_usize;
        let mut profiles = Vec::with_capacity(profile_count);
        let mut previous_id: Option<Vec<u8>> = None;
        for _ in 0..profile_count {
            let id_len_bytes = bytes
                .get(offset..offset + 2)
                .ok_or(Error::InvalidVaultPayload("truncated profile ID length"))?;
            let id_len = u16::from_le_bytes(id_len_bytes.try_into().expect("fixed range")) as usize;
            offset += 2;
            if id_len == 0 || id_len > MAX_PROFILE_ID_BYTES {
                return Err(Error::InvalidProfileId);
            }
            let id_bytes = bytes
                .get(offset..offset + id_len)
                .ok_or(Error::InvalidVaultPayload("truncated profile ID"))?;
            offset += id_len;
            let id = std::str::from_utf8(id_bytes)
                .map_err(|_| Error::InvalidVaultPayload("profile ID is not UTF-8"))?
                .to_owned();
            let key_bytes = bytes
                .get(offset..offset + 32)
                .ok_or(Error::InvalidVaultPayload("truncated profile key"))?;
            offset += 32;
            if previous_id
                .as_deref()
                .is_some_and(|previous| previous >= id_bytes)
            {
                if previous_id.as_deref() == Some(id_bytes) {
                    return Err(Error::DuplicateProfileId);
                }
                return Err(Error::UnsortedProfiles);
            }
            previous_id = Some(id_bytes.to_vec());
            profiles.push(VaultProfile {
                id,
                key: key_bytes.try_into().expect("fixed range"),
            });
        }
        if offset != bytes.len() {
            return Err(Error::InvalidVaultPayload("trailing payload bytes"));
        }
        Ok(Self {
            created_at,
            master_key,
            profiles,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.profiles.len() > MAX_PROFILES {
            return Err(Error::TooManyProfiles);
        }
        let mut previous: Option<&[u8]> = None;
        for profile in &self.profiles {
            profile.validate()?;
            if let Some(previous) = previous {
                if previous == profile.id.as_bytes() {
                    return Err(Error::DuplicateProfileId);
                }
                if previous > profile.id.as_bytes() {
                    return Err(Error::UnsortedProfiles);
                }
            }
            previous = Some(profile.id.as_bytes());
        }
        Ok(())
    }
}

impl std::fmt::Debug for VaultPayload {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VaultPayload")
            .field("created_at", &self.created_at)
            .field("master_key", &"[redacted]")
            .field("profiles", &self.profiles)
            .finish()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ContainerRandomness {
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
}

impl ContainerRandomness {
    pub fn generate() -> Result<Self> {
        let mut output = Self {
            salt: [0_u8; 16],
            nonce: [0_u8; 24],
        };
        random_bytes(&mut output.salt)?;
        random_bytes(&mut output.nonce)?;
        Ok(output)
    }
}

#[derive(Clone, Copy)]
pub(crate) enum ContainerKind {
    Vault,
    Recovery,
}

impl ContainerKind {
    fn magic(self) -> &'static [u8; 6] {
        match self {
            Self::Vault => VAULT_MAGIC,
            Self::Recovery => b"TDREC2",
        }
    }

    fn aad(self) -> &'static [u8] {
        match self {
            Self::Vault => VAULT_AAD,
            Self::Recovery => RECOVERY_AAD,
        }
    }
}

pub fn seal_vault(payload: &VaultPayload, passphrase: &[u8]) -> Result<Vec<u8>> {
    seal_vault_with_options(payload, passphrase, Argon2Params::WRITER_DEFAULT)
}

pub fn seal_vault_with_options(
    payload: &VaultPayload,
    passphrase: &[u8],
    argon2: Argon2Params,
) -> Result<Vec<u8>> {
    seal_container(
        ContainerKind::Vault,
        payload,
        passphrase,
        argon2,
        ContainerRandomness::generate()?,
    )
}

pub fn seal_vault_with_randomness(
    payload: &VaultPayload,
    passphrase: &[u8],
    argon2: Argon2Params,
    randomness: ContainerRandomness,
) -> Result<Vec<u8>> {
    seal_container(
        ContainerKind::Vault,
        payload,
        passphrase,
        argon2,
        randomness,
    )
}

pub fn open_vault(container: &[u8], passphrase: &[u8]) -> Result<VaultPayload> {
    open_container(ContainerKind::Vault, container, passphrase)
}

pub(crate) fn seal_container(
    kind: ContainerKind,
    payload: &VaultPayload,
    passphrase: &[u8],
    argon2: Argon2Params,
    randomness: ContainerRandomness,
) -> Result<Vec<u8>> {
    argon2.validate()?;
    let plaintext = ZeroizeOnDropVec::new(payload.to_bytes()?);
    if matches!(kind, ContainerKind::Recovery) && plaintext.0.len() > MAX_RECOVERY_PAYLOAD_BYTES {
        return Err(Error::RecoveryPayloadTooLarge);
    }
    let ciphertext_len = plaintext
        .0
        .len()
        .checked_add(16)
        .ok_or(Error::LengthOverflow)?;
    let ciphertext_len = u32::try_from(ciphertext_len).map_err(|_| Error::LengthOverflow)?;
    let mut header = [0_u8; CONTAINER_HEADER_BYTES];
    header[0..6].copy_from_slice(kind.magic());
    header[6..8].copy_from_slice(&2_u16.to_le_bytes());
    header[8..12].copy_from_slice(&argon2.memory_kib.to_le_bytes());
    header[12..16].copy_from_slice(&argon2.iterations.to_le_bytes());
    header[16..20].copy_from_slice(&argon2.parallelism.to_le_bytes());
    header[20..36].copy_from_slice(&randomness.salt);
    header[36..60].copy_from_slice(&randomness.nonce);
    header[60..64].copy_from_slice(&ciphertext_len.to_le_bytes());
    let key = argon2.derive(passphrase, &randomness.salt)?;
    let mut aad = Vec::with_capacity(kind.aad().len() + CONTAINER_HEADER_BYTES);
    aad.extend_from_slice(kind.aad());
    aad.extend_from_slice(&header);
    let ciphertext = seal(&key, &randomness.nonce, &aad, &plaintext.0)?;
    let mut output = Vec::with_capacity(CONTAINER_HEADER_BYTES + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub(crate) fn open_container(
    kind: ContainerKind,
    container: &[u8],
    passphrase: &[u8],
) -> Result<VaultPayload> {
    if container.len() < CONTAINER_HEADER_BYTES {
        return Err(Error::Truncated("vault container header"));
    }
    let header = &container[..CONTAINER_HEADER_BYTES];
    if &header[..6] != kind.magic() {
        return Err(Error::InvalidMagic);
    }
    let version = u16::from_le_bytes([header[6], header[7]]);
    if version != 2 {
        return Err(Error::UnsupportedVersion(version));
    }
    let argon2 = Argon2Params {
        memory_kib: u32::from_le_bytes(header[8..12].try_into().expect("fixed range")),
        iterations: u32::from_le_bytes(header[12..16].try_into().expect("fixed range")),
        parallelism: u32::from_le_bytes(header[16..20].try_into().expect("fixed range")),
    };
    argon2.validate()?;
    let ciphertext_len =
        u32::from_le_bytes(header[60..64].try_into().expect("fixed range")) as usize;
    if ciphertext_len < 16 {
        return Err(Error::InvalidVaultPayload("invalid ciphertext length"));
    }
    let expected_len = CONTAINER_HEADER_BYTES
        .checked_add(ciphertext_len)
        .ok_or(Error::LengthOverflow)?;
    if container.len() < expected_len {
        return Err(Error::Truncated("vault container ciphertext"));
    }
    if container.len() > expected_len {
        return Err(Error::TrailingBytes);
    }
    let plaintext_len = ciphertext_len - 16;
    match kind {
        ContainerKind::Recovery if plaintext_len > MAX_RECOVERY_PAYLOAD_BYTES => {
            return Err(Error::RecoveryPayloadTooLarge);
        }
        ContainerKind::Vault if plaintext_len > MAX_VAULT_PAYLOAD_BYTES => {
            return Err(Error::InvalidVaultPayload(
                "payload exceeds the profile bounds",
            ));
        }
        _ => {}
    }
    let salt: &[u8; 16] = header[20..36].try_into().expect("fixed range");
    let nonce: &[u8; 24] = header[36..60].try_into().expect("fixed range");
    let key = argon2.derive(passphrase, salt)?;
    let mut aad = Vec::with_capacity(kind.aad().len() + CONTAINER_HEADER_BYTES);
    aad.extend_from_slice(kind.aad());
    aad.extend_from_slice(header);
    let plaintext = open(
        &key,
        nonce,
        &aad,
        &container[CONTAINER_HEADER_BYTES..],
        "vault-container authentication",
    )?;
    VaultPayload::from_bytes(&plaintext)
}

struct ZeroizeOnDropVec(Vec<u8>);

impl ZeroizeOnDropVec {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Drop for ZeroizeOnDropVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
