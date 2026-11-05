use std::collections::BTreeSet;
use std::io::Read;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result};
use crate::kdf::{Argon2Params, hkdf_key, hmac_sha256, open, seal, verify_hmac_sha256};
use crate::metadata::{MAX_METADATA_PLAINTEXT, ProtectedMetadata};

pub const MAGIC: &[u8; 6] = b"TDENC2";
pub const VERSION: u16 = 2;
pub const CIPHER_SUITE_XCHACHA20_POLY1305: u16 = 1;
pub const FIXED_HEADER_BYTES: usize = 98;
pub const KEY_SLOT_BYTES: usize = 104;
pub const MAX_HEADER_BYTES: usize = 65_536;
pub const MIN_SLOTS: usize = 1;
pub const MAX_SLOTS: usize = 8;
pub const MIN_CHUNK_SIZE: u32 = 65_536;
pub const MAX_CHUNK_SIZE: u32 = 16_777_216;
pub const WRITER_CHUNK_SIZE: u32 = 1_048_576;
pub const FINAL_RECORD_BYTES: usize = 68;

pub(crate) const FILE_WRAP_INFO: &[u8] = b"telegram-drive:file-wrap:v2";
pub(crate) const KEY_SLOT_AAD: &[u8] = b"telegram-drive:tdenc2:key-slot";
pub(crate) const HEADER_AUTH_INFO: &[u8] = b"telegram-drive:header-auth:v2";
pub(crate) const METADATA_ENC_INFO: &[u8] = b"telegram-drive:metadata-enc:v2";
pub(crate) const CONTENT_ENC_INFO: &[u8] = b"telegram-drive:content-enc:v2";
pub(crate) const HEADER_MAC_DOMAIN: &[u8] = b"telegram-drive:tdenc2:header-mac";
pub(crate) const METADATA_AAD: &[u8] = b"telegram-drive:tdenc2:metadata";

pub(crate) type DataKey = Zeroizing<[u8; 32]>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SlotKind {
    Vault = 1,
    Passphrase = 2,
    Recovery = 3,
}

impl TryFrom<u8> for SlotKind {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Vault),
            2 => Ok(Self::Passphrase),
            3 => Ok(Self::Recovery),
            other => Err(Error::InvalidSlotKind(other)),
        }
    }
}

/// A credential used to create or unwrap a key slot. Secrets are zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub enum Credential {
    VaultKey([u8; 32]),
    Passphrase(Vec<u8>),
    RecoveryKey([u8; 32]),
}

impl Credential {
    pub fn vault_key(key: [u8; 32]) -> Self {
        Self::VaultKey(key)
    }

    pub fn passphrase(passphrase: impl AsRef<[u8]>) -> Self {
        Self::Passphrase(passphrase.as_ref().to_vec())
    }

    pub fn recovery_key(key: [u8; 32]) -> Self {
        Self::RecoveryKey(key)
    }

    fn matches(&self, kind: SlotKind) -> bool {
        matches!(
            (self, kind),
            (Self::Passphrase(_), SlotKind::Passphrase)
                | (
                    Self::VaultKey(_) | Self::RecoveryKey(_),
                    SlotKind::Vault | SlotKind::Recovery
                )
        )
    }
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::VaultKey(_) => "Credential::VaultKey([redacted])",
            Self::Passphrase(_) => "Credential::Passphrase([redacted])",
            Self::RecoveryKey(_) => "Credential::RecoveryKey([redacted])",
        })
    }
}

/// The fixed-size, independently authenticated wrapping record for one credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeySlot {
    pub kind: SlotKind,
    pub id: u8,
    pub argon2: Option<Argon2Params>,
    pub salt: [u8; 16],
    pub wrapping_nonce: [u8; 24],
    pub wrapped_dek: [u8; 48],
}

impl KeySlot {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_with_randomness(
        credential: &Credential,
        id: u8,
        argon2: Argon2Params,
        uuid: &[u8; 16],
        dek: &[u8; 32],
        salt: [u8; 16],
        wrapping_nonce: [u8; 24],
    ) -> Result<Self> {
        let (kind, params, wrapping_key) = match credential {
            Credential::VaultKey(master_key) => (
                SlotKind::Vault,
                None,
                hkdf_key(
                    master_key,
                    Some(&salt),
                    &wrap_info(uuid, SlotKind::Vault, id),
                ),
            ),
            Credential::RecoveryKey(master_key) => (
                SlotKind::Recovery,
                None,
                hkdf_key(
                    master_key,
                    Some(&salt),
                    &wrap_info(uuid, SlotKind::Recovery, id),
                ),
            ),
            Credential::Passphrase(passphrase) => (
                SlotKind::Passphrase,
                Some(argon2.validate()?),
                argon2.derive(passphrase, &salt)?,
            ),
        };
        let mut slot = Self {
            kind,
            id,
            argon2: params,
            salt,
            wrapping_nonce,
            wrapped_dek: [0_u8; 48],
        };
        let aad = slot.wrapping_aad(uuid);
        let ciphertext = seal(&wrapping_key, &wrapping_nonce, &aad, dek)?;
        if ciphertext.len() != 48 {
            return Err(Error::LengthOverflow);
        }
        slot.wrapped_dek.copy_from_slice(&ciphertext);
        Ok(slot)
    }

    pub fn encode(&self) -> [u8; KEY_SLOT_BYTES] {
        let mut output = [0_u8; KEY_SLOT_BYTES];
        output[0] = self.kind as u8;
        output[1] = self.id;
        let (kdf, params) = match (self.kind, self.argon2) {
            (SlotKind::Passphrase, Some(params)) => (1_u16, params),
            _ => (
                2_u16,
                Argon2Params {
                    memory_kib: 0,
                    iterations: 0,
                    parallelism: 0,
                },
            ),
        };
        output[2..4].copy_from_slice(&kdf.to_le_bytes());
        output[4..8].copy_from_slice(&params.memory_kib.to_le_bytes());
        output[8..12].copy_from_slice(&params.iterations.to_le_bytes());
        output[12..16].copy_from_slice(&params.parallelism.to_le_bytes());
        output[16..32].copy_from_slice(&self.salt);
        output[32..56].copy_from_slice(&self.wrapping_nonce);
        output[56..104].copy_from_slice(&self.wrapped_dek);
        output
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SLOT_BYTES {
            return Err(Error::InvalidSlotTableLength);
        }
        let kind = SlotKind::try_from(bytes[0])?;
        let kdf = u16::from_le_bytes([bytes[2], bytes[3]]);
        let params = Argon2Params {
            memory_kib: u32::from_le_bytes(bytes[4..8].try_into().expect("fixed range")),
            iterations: u32::from_le_bytes(bytes[8..12].try_into().expect("fixed range")),
            parallelism: u32::from_le_bytes(bytes[12..16].try_into().expect("fixed range")),
        };
        let argon2 = match (kind, kdf) {
            (SlotKind::Passphrase, 1) => {
                params.validate()?;
                Some(params)
            }
            (SlotKind::Vault | SlotKind::Recovery, 2) => {
                if params.memory_kib != 0 || params.iterations != 0 || params.parallelism != 0 {
                    return Err(Error::InvalidHkdfFields);
                }
                None
            }
            _ => return Err(Error::InvalidSlotKdf),
        };
        Ok(Self {
            kind,
            id: bytes[1],
            argon2,
            salt: bytes[16..32].try_into().expect("fixed range"),
            wrapping_nonce: bytes[32..56].try_into().expect("fixed range"),
            wrapped_dek: bytes[56..104].try_into().expect("fixed range"),
        })
    }

    fn wrapping_aad(&self, uuid: &[u8; 16]) -> Vec<u8> {
        let mut output = Vec::with_capacity(KEY_SLOT_AAD.len() + 44);
        output.extend_from_slice(KEY_SLOT_AAD);
        output.extend_from_slice(&VERSION.to_le_bytes());
        output.extend_from_slice(uuid);
        output.push(self.kind as u8);
        output.push(self.id);
        match self.argon2 {
            Some(params) => {
                output.extend_from_slice(&1_u16.to_le_bytes());
                output.extend_from_slice(&params.memory_kib.to_le_bytes());
                output.extend_from_slice(&params.iterations.to_le_bytes());
                output.extend_from_slice(&params.parallelism.to_le_bytes());
            }
            None => {
                output.extend_from_slice(&2_u16.to_le_bytes());
                output.extend_from_slice(&0_u32.to_le_bytes());
                output.extend_from_slice(&0_u32.to_le_bytes());
                output.extend_from_slice(&0_u32.to_le_bytes());
            }
        }
        output.extend_from_slice(&self.salt);
        output
    }

    fn unwrap(&self, uuid: &[u8; 16], credential: &Credential) -> Result<DataKey> {
        let wrapping_key = match (self.kind, credential) {
            (SlotKind::Passphrase, Credential::Passphrase(passphrase)) => self
                .argon2
                .ok_or(Error::InvalidSlotKdf)?
                .derive(passphrase, &self.salt)?,
            (SlotKind::Vault | SlotKind::Recovery, Credential::VaultKey(key))
            | (SlotKind::Vault | SlotKind::Recovery, Credential::RecoveryKey(key)) => {
                hkdf_key(key, Some(&self.salt), &wrap_info(uuid, self.kind, self.id))
            }
            _ => return Err(Error::MissingCredential(self.id)),
        };
        let plaintext = open(
            &wrapping_key,
            &self.wrapping_nonce,
            &self.wrapping_aad(uuid),
            &self.wrapped_dek,
            "key-slot unwrapping",
        )?;
        if plaintext.len() != 32 {
            return Err(Error::AuthenticationFailed("key-slot unwrapping"));
        }
        let mut dek = Zeroizing::new([0_u8; 32]);
        dek.copy_from_slice(&plaintext);
        Ok(dek)
    }
}

fn wrap_info(uuid: &[u8; 16], kind: SlotKind, id: u8) -> Vec<u8> {
    let mut info = Vec::with_capacity(FILE_WRAP_INFO.len() + 18);
    info.extend_from_slice(FILE_WRAP_INFO);
    info.extend_from_slice(uuid);
    info.push(kind as u8);
    info.push(id);
    info
}

/// A structurally validated header. Metadata remains encrypted until `unlock` succeeds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Header {
    pub uuid: [u8; 16],
    pub chunk_size: u32,
    pub total_plaintext_len: u64,
    pub nonce_prefix: [u8; 16],
    pub header_authenticator: [u8; 32],
    pub slots: Vec<KeySlot>,
    encrypted_metadata: Vec<u8>,
}

impl Header {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FIXED_HEADER_BYTES {
            return Err(Error::Truncated("TDENC2 fixed header"));
        }
        if &bytes[0..6] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        let version = u16::from_le_bytes([bytes[6], bytes[7]]);
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let suite = u16::from_le_bytes([bytes[24], bytes[25]]);
        if suite != CIPHER_SUITE_XCHACHA20_POLY1305 {
            return Err(Error::UnsupportedCipherSuite(suite));
        }
        let header_len =
            u32::from_le_bytes(bytes[26..30].try_into().expect("fixed range")) as usize;
        if header_len > MAX_HEADER_BYTES {
            return Err(Error::HeaderTooLarge);
        }
        if header_len < FIXED_HEADER_BYTES {
            return Err(Error::InvalidHeaderLength);
        }
        if bytes.len() < header_len {
            return Err(Error::Truncated("complete TDENC2 header"));
        }
        if bytes.len() != header_len {
            return Err(Error::InvalidHeaderLength);
        }
        let chunk_size = u32::from_le_bytes(bytes[30..34].try_into().expect("fixed range"));
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(Error::InvalidChunkSize);
        }
        let slots_len = u32::from_le_bytes(bytes[34..38].try_into().expect("fixed range")) as usize;
        if !slots_len.is_multiple_of(KEY_SLOT_BYTES) {
            return Err(Error::InvalidSlotTableLength);
        }
        let slot_count = slots_len / KEY_SLOT_BYTES;
        if !(MIN_SLOTS..=MAX_SLOTS).contains(&slot_count) {
            return Err(Error::InvalidSlotCount);
        }
        let metadata_len =
            u32::from_le_bytes(bytes[38..42].try_into().expect("fixed range")) as usize;
        if metadata_len != 0 && metadata_len < 16 {
            return Err(Error::InvalidMetadataLength);
        }
        if FIXED_HEADER_BYTES
            .checked_add(slots_len)
            .and_then(|value| value.checked_add(metadata_len))
            != Some(header_len)
        {
            return Err(Error::InvalidHeaderLength);
        }
        let mut slots = Vec::with_capacity(slot_count);
        let mut ids = BTreeSet::new();
        for slot_bytes in bytes[FIXED_HEADER_BYTES..FIXED_HEADER_BYTES + slots_len]
            .as_chunks::<KEY_SLOT_BYTES>()
            .0
        {
            let slot = KeySlot::decode(slot_bytes)?;
            if !ids.insert(slot.id) {
                return Err(Error::DuplicateSlotId(slot.id));
            }
            slots.push(slot);
        }
        Ok(Self {
            uuid: bytes[8..24].try_into().expect("fixed range"),
            chunk_size,
            total_plaintext_len: u64::from_le_bytes(bytes[42..50].try_into().expect("fixed range")),
            nonce_prefix: bytes[50..66].try_into().expect("fixed range"),
            header_authenticator: bytes[66..98].try_into().expect("fixed range"),
            slots,
            encrypted_metadata: bytes[FIXED_HEADER_BYTES + slots_len..header_len].to_vec(),
        })
    }

    /// Reads exactly one header and leaves the reader positioned at the first content record.
    pub fn read_from(reader: &mut impl Read) -> Result<Self> {
        let mut fixed = [0_u8; FIXED_HEADER_BYTES];
        read_exact(reader, &mut fixed, "TDENC2 fixed header")?;
        if &fixed[0..6] != MAGIC {
            return Err(Error::InvalidMagic);
        }
        let header_len =
            u32::from_le_bytes(fixed[26..30].try_into().expect("fixed range")) as usize;
        if header_len > MAX_HEADER_BYTES {
            return Err(Error::HeaderTooLarge);
        }
        if header_len < FIXED_HEADER_BYTES {
            return Err(Error::InvalidHeaderLength);
        }
        let mut complete = vec![0_u8; header_len];
        complete[..FIXED_HEADER_BYTES].copy_from_slice(&fixed);
        read_exact(
            reader,
            &mut complete[FIXED_HEADER_BYTES..],
            "complete TDENC2 header",
        )?;
        Self::parse(&complete)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let slots = self.encoded_slots();
        let header_len = FIXED_HEADER_BYTES
            .checked_add(slots.len())
            .and_then(|value| value.checked_add(self.encrypted_metadata.len()))
            .ok_or(Error::LengthOverflow)?;
        if header_len > MAX_HEADER_BYTES {
            return Err(Error::HeaderTooLarge);
        }
        let mut prefix = self.prefix()?;
        let mut output = Vec::with_capacity(header_len);
        output.append(&mut prefix);
        output.extend_from_slice(&self.header_authenticator);
        output.extend_from_slice(&slots);
        output.extend_from_slice(&self.encrypted_metadata);
        Ok(output)
    }

    pub fn encrypted_metadata(&self) -> Option<&[u8]> {
        (!self.encrypted_metadata.is_empty()).then_some(&self.encrypted_metadata)
    }

    pub fn chunk_count(&self) -> Result<u32> {
        chunk_count(self.total_plaintext_len, self.chunk_size)
    }

    pub fn expected_ciphertext_len(&self) -> Result<u64> {
        expected_ciphertext_len(self)
    }

    /// Unlocks any usable slot, authenticates the complete header, then decrypts metadata.
    pub fn unlock(&self, credentials: &[Credential]) -> Result<UnlockedHeader> {
        self.unlock_internal(credentials, false)
    }

    /// Requires every slot to unwrap with the currently supplied credentials.
    pub fn unlock_all(&self, credentials: &[Credential]) -> Result<UnlockedHeader> {
        self.unlock_internal(credentials, true)
    }

    pub(crate) fn build(
        uuid: [u8; 16],
        nonce_prefix: [u8; 16],
        total_plaintext_len: u64,
        slots: Vec<KeySlot>,
        metadata: Option<&ProtectedMetadata>,
        dek: &[u8; 32],
    ) -> Result<Self> {
        if slots.len() < MIN_SLOTS || slots.len() > MAX_SLOTS {
            return Err(Error::InvalidSlotCount);
        }
        let metadata_plaintext = metadata.map(ProtectedMetadata::to_bytes).transpose()?;
        if let Some(plaintext) = &metadata_plaintext
            && plaintext.len() > MAX_METADATA_PLAINTEXT
        {
            return Err(Error::MetadataTooLarge);
        }
        let mut header = Self {
            uuid,
            chunk_size: WRITER_CHUNK_SIZE,
            total_plaintext_len,
            nonce_prefix,
            header_authenticator: [0_u8; 32],
            slots,
            encrypted_metadata: Vec::new(),
        };
        let slots_bytes = header.encoded_slots();
        if let Some(plaintext) = metadata_plaintext {
            let capacity = MAX_HEADER_BYTES - FIXED_HEADER_BYTES - slots_bytes.len() - 16;
            if plaintext.len() > capacity {
                return Err(Error::MetadataTooLarge);
            }
            let key = hkdf_key(dek, None, METADATA_ENC_INFO);
            // The authenticated prefix declares the ciphertext length, including its tag.
            header.encrypted_metadata = vec![0_u8; plaintext.len() + 16];
            let aad = header.metadata_aad(&slots_bytes);
            let nonce = header.content_nonce(u64::MAX);
            header.encrypted_metadata = seal(&key, &nonce, &aad, &plaintext)?;
        }
        let key = hkdf_key(dek, None, HEADER_AUTH_INFO);
        header.header_authenticator = hmac_sha256(
            &key[..],
            &[
                HEADER_MAC_DOMAIN,
                &header.prefix()?,
                &slots_bytes,
                &header.encrypted_metadata,
            ],
        );
        Ok(header)
    }

    pub(crate) fn content_nonce(&self, counter: u64) -> [u8; 24] {
        let mut nonce = [0_u8; 24];
        nonce[..16].copy_from_slice(&self.nonce_prefix);
        nonce[16..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    pub(crate) fn content_key(&self, dek: &[u8; 32]) -> DataKey {
        hkdf_key(dek, None, CONTENT_ENC_INFO)
    }

    pub(crate) fn encoded_slots(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.slots.len() * KEY_SLOT_BYTES);
        for slot in &self.slots {
            output.extend_from_slice(&slot.encode());
        }
        output
    }

    pub(crate) fn prefix(&self) -> Result<Vec<u8>> {
        if self.slots.len() < MIN_SLOTS || self.slots.len() > MAX_SLOTS {
            return Err(Error::InvalidSlotCount);
        }
        if !(MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&self.chunk_size) {
            return Err(Error::InvalidChunkSize);
        }
        let mut prefix = Vec::with_capacity(66);
        prefix.extend_from_slice(MAGIC);
        prefix.extend_from_slice(&VERSION.to_le_bytes());
        prefix.extend_from_slice(&self.uuid);
        prefix.extend_from_slice(&CIPHER_SUITE_XCHACHA20_POLY1305.to_le_bytes());
        let header_len =
            FIXED_HEADER_BYTES + self.slots.len() * KEY_SLOT_BYTES + self.encrypted_metadata.len();
        let header_len = u32::try_from(header_len).map_err(|_| Error::HeaderTooLarge)?;
        prefix.extend_from_slice(&header_len.to_le_bytes());
        prefix.extend_from_slice(&self.chunk_size.to_le_bytes());
        prefix.extend_from_slice(
            &u32::try_from(self.slots.len() * KEY_SLOT_BYTES)
                .map_err(|_| Error::InvalidSlotTableLength)?
                .to_le_bytes(),
        );
        prefix.extend_from_slice(
            &u32::try_from(self.encrypted_metadata.len())
                .map_err(|_| Error::InvalidMetadataLength)?
                .to_le_bytes(),
        );
        prefix.extend_from_slice(&self.total_plaintext_len.to_le_bytes());
        prefix.extend_from_slice(&self.nonce_prefix);
        Ok(prefix)
    }

    fn metadata_aad(&self, slots: &[u8]) -> Vec<u8> {
        let prefix = self.prefix().expect("structurally validated header");
        let mut aad = Vec::with_capacity(METADATA_AAD.len() + prefix.len() + slots.len());
        aad.extend_from_slice(METADATA_AAD);
        aad.extend_from_slice(&prefix);
        aad.extend_from_slice(slots);
        aad
    }

    fn unlock_internal(
        &self,
        credentials: &[Credential],
        require_all: bool,
    ) -> Result<UnlockedHeader> {
        let mut selected: Option<DataKey> = None;
        let mut any_matching_credential = false;
        for slot in &self.slots {
            let mut matching = false;
            let mut unlocked = None;
            let mut last_error = None;
            for credential in credentials.iter().filter(|item| item.matches(slot.kind)) {
                matching = true;
                any_matching_credential = true;
                match slot.unwrap(&self.uuid, credential) {
                    Ok(dek) => {
                        unlocked = Some(dek);
                        break;
                    }
                    Err(error) => last_error = Some(error),
                }
            }
            if let Some(dek) = unlocked {
                if let Some(existing) = &selected {
                    if existing.as_ref() != dek.as_ref() {
                        return Err(Error::InconsistentDataKeys);
                    }
                } else {
                    selected = Some(dek);
                }
            } else if require_all {
                if !matching {
                    return Err(Error::MissingCredential(slot.id));
                }
                return Err(last_error.unwrap_or(Error::MissingCredential(slot.id)));
            }
        }
        if selected.is_none() && !any_matching_credential {
            return Err(Error::MissingCredential(self.slots[0].id));
        }
        let dek = selected.ok_or(Error::AuthenticationFailed("key-slot unwrapping"))?;
        let header_key = hkdf_key(&dek[..], None, HEADER_AUTH_INFO);
        let prefix = self.prefix()?;
        let slots = self.encoded_slots();
        if !verify_hmac_sha256(
            &header_key[..],
            &[HEADER_MAC_DOMAIN, &prefix, &slots, &self.encrypted_metadata],
            &self.header_authenticator,
        ) {
            return Err(Error::AuthenticationFailed("header authentication"));
        }
        let (metadata, metadata_plaintext) = if self.encrypted_metadata.is_empty() {
            (None, None)
        } else {
            let key = hkdf_key(&dek[..], None, METADATA_ENC_INFO);
            let aad = self.metadata_aad(&slots);
            let nonce = self.content_nonce(u64::MAX);
            let plaintext = open(
                &key,
                &nonce,
                &aad,
                &self.encrypted_metadata,
                "metadata authentication",
            )?;
            let parsed = ProtectedMetadata::from_bytes(&plaintext)?;
            (Some(parsed), Some(plaintext))
        };
        Ok(UnlockedHeader {
            header: self.clone(),
            dek,
            metadata,
            metadata_plaintext,
        })
    }
}

/// Header material whose HMAC and optional metadata have both authenticated successfully.
#[derive(Clone)]
pub struct UnlockedHeader {
    pub(crate) header: Header,
    pub(crate) dek: DataKey,
    pub(crate) metadata: Option<ProtectedMetadata>,
    pub(crate) metadata_plaintext: Option<Zeroizing<Vec<u8>>>,
}

impl UnlockedHeader {
    pub fn header(&self) -> &Header {
        &self.header
    }

    pub fn metadata(&self) -> Option<&ProtectedMetadata> {
        self.metadata.as_ref()
    }

    pub fn metadata_bytes(&self) -> Option<&[u8]> {
        self.metadata_plaintext.as_deref().map(Vec::as_ref)
    }

    pub fn expected_ciphertext_len(&self) -> Result<u64> {
        self.header.expected_ciphertext_len()
    }
}

pub(crate) fn chunk_count(total_len: u64, chunk_size: u32) -> Result<u32> {
    let count = if total_len == 0 {
        0
    } else {
        (total_len - 1) / u64::from(chunk_size) + 1
    };
    u32::try_from(count).map_err(|_| Error::ChunkCountOverflow)
}

pub(crate) fn expected_ciphertext_len(header: &Header) -> Result<u64> {
    let chunks = u64::from(header.chunk_count()?);
    u64::try_from(header.to_bytes()?.len())
        .map_err(|_| Error::LengthOverflow)?
        .checked_add(header.total_plaintext_len)
        .and_then(|value| value.checked_add(chunks.checked_mul(16)?))
        .and_then(|value| value.checked_add(FINAL_RECORD_BYTES as u64))
        .ok_or(Error::LengthOverflow)
}

fn read_exact(reader: &mut impl Read, mut output: &mut [u8], context: &'static str) -> Result<()> {
    while !output.is_empty() {
        let count = reader.read(output)?;
        if count == 0 {
            return Err(Error::Truncated(context));
        }
        output = &mut output[count..];
    }
    Ok(())
}
