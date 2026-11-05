use std::io::{Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{Error, Result, random_bytes};
use crate::header::{Credential, KeySlot};
use crate::header::{FINAL_RECORD_BYTES, Header, UnlockedHeader, WRITER_CHUNK_SIZE};
use crate::kdf::{Argon2Params, open, seal};
use crate::metadata::ProtectedMetadata;

const CHUNK_AAD: &[u8] = b"telegram-drive:tdenc2:chunk";
const FINAL_AAD: &[u8] = b"telegram-drive:tdenc2:final";

/// Random envelope material. Reusing it with different plaintext is forbidden.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SessionRandomness {
    pub dek: [u8; 32],
    pub uuid: [u8; 16],
    pub nonce_prefix: [u8; 16],
}

impl SessionRandomness {
    pub fn generate() -> Result<Self> {
        let mut output = Self {
            dek: [0_u8; 32],
            uuid: [0_u8; 16],
            nonce_prefix: [0_u8; 16],
        };
        random_bytes(&mut output.dek)?;
        random_bytes(&mut output.uuid)?;
        random_bytes(&mut output.nonce_prefix)?;
        Ok(output)
    }
}

/// Independent random inputs for one key slot. Every slot needs a fresh value.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SlotRandomness {
    pub salt: [u8; 16],
    pub wrapping_nonce: [u8; 24],
}

impl SlotRandomness {
    pub fn generate() -> Result<Self> {
        let mut output = Self {
            salt: [0_u8; 16],
            wrapping_nonce: [0_u8; 24],
        };
        random_bytes(&mut output.salt)?;
        random_bytes(&mut output.wrapping_nonce)?;
        Ok(output)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferSummary {
    pub chunk_count: u32,
    pub plaintext_len: u64,
    pub plaintext_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecryptedEnvelope {
    pub metadata: Option<ProtectedMetadata>,
    pub summary: TransferSummary,
}

/// An authenticated, reusable encryption session with a fixed DEK and complete header.
pub struct EncryptionSession {
    unlocked: UnlockedHeader,
    complete_header: Vec<u8>,
}

impl EncryptionSession {
    /// Creates a fresh envelope using operating-system randomness and 1 MiB writer chunks.
    pub fn new(
        total_plaintext_len: u64,
        metadata: Option<ProtectedMetadata>,
        credentials: &[Credential],
    ) -> Result<Self> {
        Self::with_argon2(
            total_plaintext_len,
            metadata,
            credentials,
            Argon2Params::WRITER_DEFAULT,
        )
    }

    pub fn with_argon2(
        total_plaintext_len: u64,
        metadata: Option<ProtectedMetadata>,
        credentials: &[Credential],
        argon2: Argon2Params,
    ) -> Result<Self> {
        let randomness = SessionRandomness::generate()?;
        let mut slot_randomness = Vec::with_capacity(credentials.len());
        for _ in credentials {
            slot_randomness.push(SlotRandomness::generate()?);
        }
        Self::new_with_randomness(
            total_plaintext_len,
            metadata,
            credentials,
            argon2,
            randomness,
            &slot_randomness,
        )
    }

    /// Deterministic constructor for controlled interoperability producers.
    ///
    /// The caller must guarantee a fresh DEK and nonce prefix for every distinct plaintext.
    /// Reusing this material for changed plaintext breaks XChaCha20-Poly1305 confidentiality
    /// and integrity; continuation of identical plaintext should use `from_header` instead.
    pub fn new_with_randomness(
        total_plaintext_len: u64,
        metadata: Option<ProtectedMetadata>,
        credentials: &[Credential],
        argon2: Argon2Params,
        randomness: SessionRandomness,
        slot_randomness: &[SlotRandomness],
    ) -> Result<Self> {
        if credentials.is_empty() || credentials.len() > 8 {
            return Err(Error::InvalidSlotCount);
        }
        if slot_randomness.len() != credentials.len() {
            return Err(Error::InvalidSlotCount);
        }
        let mut slots = Vec::with_capacity(credentials.len());
        for (index, credential) in credentials.iter().enumerate() {
            slots.push(KeySlot::create_with_randomness(
                credential,
                u8::try_from(index).map_err(|_| Error::InvalidSlotCount)?,
                argon2,
                &randomness.uuid,
                &randomness.dek,
                slot_randomness[index].salt,
                slot_randomness[index].wrapping_nonce,
            )?);
        }
        let header = Header::build(
            randomness.uuid,
            randomness.nonce_prefix,
            total_plaintext_len,
            slots,
            metadata.as_ref(),
            &randomness.dek,
        )?;
        let complete_header = header.to_bytes()?;
        let metadata_plaintext = metadata
            .as_ref()
            .map(ProtectedMetadata::to_bytes)
            .transpose()?;
        Ok(Self {
            unlocked: UnlockedHeader {
                header,
                dek: Zeroizing::new(randomness.dek),
                metadata,
                metadata_plaintext: metadata_plaintext.map(Zeroizing::new),
            },
            complete_header,
        })
    }

    /// Continues an unchanged plaintext using the exact authenticated original header.
    pub fn from_header(
        complete_header: &[u8],
        expected_plaintext_len: u64,
        expected_metadata: Option<&ProtectedMetadata>,
        credentials: &[Credential],
    ) -> Result<Self> {
        let expected_metadata = expected_metadata
            .map(ProtectedMetadata::to_bytes)
            .transpose()?;
        Self::from_header_with_metadata_bytes(
            complete_header,
            expected_plaintext_len,
            expected_metadata.as_deref(),
            credentials,
        )
    }

    /// Byte-exact continuation variant for journals that store the protected JSON bytes.
    pub fn from_header_with_metadata_bytes(
        complete_header: &[u8],
        expected_plaintext_len: u64,
        expected_metadata: Option<&[u8]>,
        credentials: &[Credential],
    ) -> Result<Self> {
        let header = Header::parse(complete_header)?;
        if header.chunk_size != WRITER_CHUNK_SIZE {
            return Err(Error::InvalidWriterChunkSize);
        }
        if header.total_plaintext_len != expected_plaintext_len {
            return Err(Error::PlaintextLengthMismatch {
                expected: expected_plaintext_len,
                actual: header.total_plaintext_len,
            });
        }
        let unlocked = header.unlock_all(credentials)?;
        if unlocked.metadata_bytes() != expected_metadata {
            return Err(Error::InvalidMetadata(
                "continuation metadata or protection mode changed".to_owned(),
            ));
        }
        Ok(Self {
            unlocked,
            complete_header: complete_header.to_vec(),
        })
    }

    pub fn header(&self) -> &Header {
        &self.unlocked.header
    }

    pub fn complete_header(&self) -> &[u8] {
        &self.complete_header
    }

    pub fn metadata(&self) -> Option<&ProtectedMetadata> {
        self.unlocked.metadata()
    }

    /// Starts record encryption at plaintext offset zero.
    ///
    /// Reusing a session is permitted only for byte-identical continuation plaintext. A changed
    /// source requires a fresh session with fresh randomness.
    pub fn chunk_encryptor(&self) -> ChunkEncryptor {
        ChunkEncryptor {
            header: self.unlocked.header.clone(),
            content_key: self.unlocked.header.content_key(&self.unlocked.dek),
            next_index: 0,
            offset: 0,
            hash: Sha256::new(),
        }
    }

    /// Encrypts from the current reader position and refuses both short and extra plaintext.
    /// Reuse is restricted to byte-identical continuation plaintext; never encrypt a changed
    /// source with the same session.
    pub fn encrypt_reader(
        &self,
        reader: &mut impl Read,
        writer: &mut impl Write,
    ) -> Result<TransferSummary> {
        writer.write_all(&self.complete_header)?;
        let mut encryptor = self.chunk_encryptor();
        let mut plaintext = vec![0_u8; WRITER_CHUNK_SIZE as usize];
        let total = self.header().total_plaintext_len;
        let mut consumed = 0_u64;
        while consumed < total {
            let wanted = usize::try_from((total - consumed).min(u64::from(WRITER_CHUNK_SIZE)))
                .map_err(|_| Error::LengthOverflow)?;
            read_exact(reader, &mut plaintext[..wanted], "plaintext")?;
            consumed += wanted as u64;
            let record = encryptor.encrypt_chunk(&plaintext[..wanted])?;
            writer.write_all(&record)?;
        }
        let mut extra = [0_u8; 1];
        if read_some(reader, &mut extra)? != 0 {
            return Err(Error::PlaintextLengthMismatch {
                expected: total,
                actual: total.saturating_add(1),
            });
        }
        let final_record = encryptor.finalize()?;
        writer.write_all(&final_record.record)?;
        Ok(final_record.summary)
    }
}

pub struct FinishedEncryption {
    pub record: Vec<u8>,
    pub summary: TransferSummary,
}

/// Bounded one-record-at-a-time encryption state. `finalize` must be called exactly once.
pub struct ChunkEncryptor {
    header: Header,
    content_key: Zeroizing<[u8; 32]>,
    next_index: u32,
    offset: u64,
    hash: Sha256,
}

impl ChunkEncryptor {
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    pub fn plaintext_offset(&self) -> u64 {
        self.offset
    }

    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let expected = expected_chunk_len(&self.header, self.offset)?;
        if plaintext.is_empty() || plaintext.len() != expected {
            return Err(Error::InvalidChunkLength);
        }
        let index = self.next_index;
        let aad = chunk_aad(
            &self.header,
            u64::from(index),
            self.offset,
            plaintext.len() as u32,
        );
        let nonce = self.header.content_nonce(u64::from(index));
        let ciphertext = seal(&self.content_key, &nonce, &aad, plaintext)?;
        self.hash.update(plaintext);
        self.offset = self
            .offset
            .checked_add(plaintext.len() as u64)
            .ok_or(Error::LengthOverflow)?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(Error::ChunkCountOverflow)?;
        Ok(ciphertext)
    }

    pub fn finalize(self) -> Result<FinishedEncryption> {
        if self.offset != self.header.total_plaintext_len {
            return Err(Error::IncompletePlaintext);
        }
        let expected_count = self.header.chunk_count()?;
        if self.next_index != expected_count {
            return Err(Error::IncompletePlaintext);
        }
        let digest: [u8; 32] = self.hash.finalize().into();
        let record = final_record(&self.header, &self.content_key, self.next_index, digest)?;
        Ok(FinishedEncryption {
            record,
            summary: TransferSummary {
                chunk_count: self.next_index,
                plaintext_len: self.offset,
                plaintext_sha256: digest,
            },
        })
    }
}

/// Internal bounded record decoder. The public two-pass API withholds all writer output until
/// `finalize` has accepted the 68-byte final record and whole-file digest.
pub(crate) struct ChunkDecryptor {
    unlocked: UnlockedHeader,
    content_key: Zeroizing<[u8; 32]>,
    next_index: u32,
    offset: u64,
    hash: Sha256,
}

impl ChunkDecryptor {
    pub fn new(unlocked: UnlockedHeader) -> Self {
        let content_key = unlocked.header.content_key(&unlocked.dek);
        Self {
            unlocked,
            content_key,
            next_index: 0,
            offset: 0,
            hash: Sha256::new(),
        }
    }

    pub fn header(&self) -> &Header {
        &self.unlocked.header
    }

    pub fn metadata(&self) -> Option<&ProtectedMetadata> {
        self.unlocked.metadata()
    }

    pub fn plaintext_offset(&self) -> u64 {
        self.offset
    }

    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let expected = expected_chunk_len(self.header(), self.offset)?;
        if ciphertext.len() != expected.checked_add(16).ok_or(Error::LengthOverflow)? {
            return Err(Error::InvalidChunkLength);
        }
        let aad = chunk_aad(
            self.header(),
            u64::from(self.next_index),
            self.offset,
            expected as u32,
        );
        let nonce = self.header().content_nonce(u64::from(self.next_index));
        let plaintext = open(
            &self.content_key,
            &nonce,
            &aad,
            ciphertext,
            "content-record authentication",
        )?;
        if plaintext.len() != expected {
            return Err(Error::InvalidChunkLength);
        }
        self.hash.update(&plaintext);
        self.offset = self
            .offset
            .checked_add(expected as u64)
            .ok_or(Error::LengthOverflow)?;
        self.next_index = self
            .next_index
            .checked_add(1)
            .ok_or(Error::ChunkCountOverflow)?;
        Ok(plaintext)
    }

    pub fn finalize(self, record: &[u8]) -> Result<TransferSummary> {
        if self.offset != self.unlocked.header.total_plaintext_len
            || self.next_index != self.unlocked.header.chunk_count()?
        {
            return Err(Error::IncompletePlaintext);
        }
        if record.len() != FINAL_RECORD_BYTES {
            return Err(Error::InvalidFinalRecord);
        }
        let header = &self.unlocked.header;
        let nonce = header.content_nonce(u64::MAX - 1);
        let aad = final_aad(header, self.next_index);
        let plaintext = open(
            &self.content_key,
            &nonce,
            &aad,
            record,
            "final-record authentication",
        )?;
        if plaintext.len() != 52 || plaintext[44..52] != [0_u8; 8] {
            return Err(Error::InvalidFinalRecord);
        }
        let final_count = u32::from_le_bytes(plaintext[0..4].try_into().expect("fixed range"));
        let final_len = u64::from_le_bytes(plaintext[4..12].try_into().expect("fixed range"));
        if final_count != self.next_index || final_len != self.offset {
            return Err(Error::InvalidFinalRecord);
        }
        let digest: [u8; 32] = self.hash.finalize().into();
        if !constant_time_equal(&digest, &plaintext[12..44]) {
            return Err(Error::DigestMismatch);
        }
        Ok(TransferSummary {
            chunk_count: self.next_index,
            plaintext_len: self.offset,
            plaintext_sha256: digest,
        })
    }
}

/// Two-pass decryption: the first pass authenticates the entire envelope and SHA-256 digest;
/// only then does the second pass write plaintext. The seekable source must remain unchanged.
pub fn decrypt_reader<R: Read + Seek, W: Write>(
    reader: &mut R,
    writer: &mut W,
    credentials: &[Credential],
) -> Result<DecryptedEnvelope> {
    reader.seek(SeekFrom::Start(0))?;
    let header = Header::read_from(reader)?;
    let unlocked = header.unlock(credentials)?;
    let header_len = header.to_bytes()?.len() as u64;
    let expected_len = unlocked.expected_ciphertext_len()?;
    let actual_len = reader.seek(SeekFrom::End(0))?;
    if actual_len != expected_len {
        return Err(Error::CiphertextLengthMismatch {
            expected: expected_len,
            actual: actual_len,
        });
    }

    reader.seek(SeekFrom::Start(header_len))?;
    let mut verifier = ChunkDecryptor::new(unlocked.clone());
    run_decryption_records(reader, &mut verifier, None)?;
    let mut final_record = [0_u8; FINAL_RECORD_BYTES];
    read_exact(reader, &mut final_record, "TDENC2 final record")?;
    let mut trailing = [0_u8; 1];
    if read_some(reader, &mut trailing)? != 0 {
        return Err(Error::TrailingBytes);
    }
    let metadata = verifier.metadata().cloned();
    let summary = verifier.finalize(&final_record)?;

    reader.seek(SeekFrom::Start(header_len))?;
    let mut publisher = ChunkDecryptor::new(unlocked);
    run_decryption_records(reader, &mut publisher, Some(writer))?;
    Ok(DecryptedEnvelope { metadata, summary })
}

// The optional writer keeps first-pass verification from allocating a whole-file plaintext buffer.
fn run_decryption_records<R: Read>(
    reader: &mut R,
    decryptor: &mut ChunkDecryptor,
    mut writer: Option<&mut dyn Write>,
) -> Result<()> {
    let chunk_count = decryptor.header().chunk_count()?;
    let mut ciphertext = vec![0_u8; decryptor.header().chunk_size as usize + 16];
    for _ in 0..chunk_count {
        let remaining = decryptor.header().total_plaintext_len - decryptor.plaintext_offset();
        let plaintext_len = remaining.min(u64::from(decryptor.header().chunk_size)) as usize;
        read_exact(
            reader,
            &mut ciphertext[..plaintext_len + 16],
            "TDENC2 content record",
        )?;
        let plaintext = decryptor.decrypt_chunk(&ciphertext[..plaintext_len + 16])?;
        if let Some(writer) = writer.as_deref_mut() {
            writer.write_all(&plaintext)?;
        }
    }
    Ok(())
}

fn expected_chunk_len(header: &Header, offset: u64) -> Result<usize> {
    if offset >= header.total_plaintext_len {
        return Err(Error::InvalidChunkLength);
    }
    usize::try_from((header.total_plaintext_len - offset).min(u64::from(header.chunk_size)))
        .map_err(|_| Error::LengthOverflow)
}

fn chunk_aad(header: &Header, index: u64, offset: u64, plaintext_len: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CHUNK_AAD.len() + 78);
    aad.extend_from_slice(CHUNK_AAD);
    aad.extend_from_slice(&2_u16.to_le_bytes());
    aad.extend_from_slice(&header.uuid);
    aad.extend_from_slice(&header.header_authenticator);
    aad.extend_from_slice(&index.to_le_bytes());
    aad.extend_from_slice(&offset.to_le_bytes());
    aad.extend_from_slice(&plaintext_len.to_le_bytes());
    aad.extend_from_slice(&header.total_plaintext_len.to_le_bytes());
    aad
}

fn final_aad(header: &Header, chunk_count: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FINAL_AAD.len() + 68);
    aad.extend_from_slice(FINAL_AAD);
    aad.extend_from_slice(&2_u16.to_le_bytes());
    aad.extend_from_slice(&header.uuid);
    aad.extend_from_slice(&header.header_authenticator);
    aad.extend_from_slice(&chunk_count.to_le_bytes());
    aad.extend_from_slice(&header.total_plaintext_len.to_le_bytes());
    aad
}

fn final_record(
    header: &Header,
    content_key: &[u8; 32],
    chunk_count: u32,
    digest: [u8; 32],
) -> Result<Vec<u8>> {
    let mut plaintext = Zeroizing::new([0_u8; 52]);
    plaintext[0..4].copy_from_slice(&chunk_count.to_le_bytes());
    plaintext[4..12].copy_from_slice(&header.total_plaintext_len.to_le_bytes());
    plaintext[12..44].copy_from_slice(&digest);
    let nonce = header.content_nonce(u64::MAX - 1);
    let aad = final_aad(header, chunk_count);
    let record = seal(content_key, &nonce, &aad, plaintext.as_ref())?;
    if record.len() != FINAL_RECORD_BYTES {
        return Err(Error::InvalidFinalRecord);
    }
    Ok(record)
}

fn constant_time_equal(left: &[u8; 32], right: &[u8]) -> bool {
    if right.len() != 32 {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

fn read_exact(reader: &mut impl Read, mut output: &mut [u8], context: &'static str) -> Result<()> {
    while !output.is_empty() {
        match reader.read(output) {
            Ok(0) => return Err(Error::Truncated(context)),
            Ok(count) => output = &mut output[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn read_some(reader: &mut impl Read, output: &mut [u8]) -> Result<usize> {
    loop {
        match reader.read(output) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            result => return Ok(result?),
        }
    }
}
