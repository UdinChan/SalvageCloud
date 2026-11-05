use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};

pub const ARGON2_MIN_MEMORY_KIB: u32 = 65_536;
pub const ARGON2_MAX_MEMORY_KIB: u32 = 262_144;
pub const ARGON2_MIN_ITERATIONS: u32 = 3;
pub const ARGON2_MAX_ITERATIONS: u32 = 100;
pub const ARGON2_MIN_PARALLELISM: u32 = 1;
pub const ARGON2_MAX_PARALLELISM: u32 = 8;

/// Argon2id parameters admitted by the frozen reader policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Argon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Argon2Params {
    pub const WRITER_DEFAULT: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 1,
    };

    pub fn validate(self) -> Result<Self> {
        if !(ARGON2_MIN_MEMORY_KIB..=ARGON2_MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(ARGON2_MIN_ITERATIONS..=ARGON2_MAX_ITERATIONS).contains(&self.iterations)
            || !(ARGON2_MIN_PARALLELISM..=ARGON2_MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(Error::InvalidKdfParameters);
        }
        Ok(self)
    }

    pub(crate) fn derive(self, passphrase: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
        self.validate()?;
        let params = Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| Error::InvalidKdfParameters)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut output = Zeroizing::new([0_u8; 32]);
        argon2
            .hash_password_into(passphrase, salt, output.as_mut())
            .map_err(|_| Error::KdfFailed)?;
        Ok(output)
    }
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self::WRITER_DEFAULT
    }
}

pub(crate) fn hkdf_key(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = Zeroizing::new([0_u8; 32]);
    // A 32-byte SHA-256 HKDF output cannot exceed the expansion limit.
    hkdf.expand(info, output.as_mut())
        .expect("32-byte HKDF-SHA-256 output is valid");
    output
}

pub(crate) fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA-256 accepts every key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub(crate) fn verify_hmac_sha256(key: &[u8], parts: &[&[u8]], expected: &[u8; 32]) -> bool {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC-SHA-256 accepts every key length");
    for part in parts {
        mac.update(part);
    }
    mac.verify_slice(expected).is_ok()
}

pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed("encryption"))
}

pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8; 24],
    aad: &[u8],
    ciphertext: &[u8],
    context: &'static str,
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::AuthenticationFailed(context))
}
