use std::path::{Path, PathBuf};

use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use rand::RngCore;
use zeroize::Zeroizing;

use crate::{CoreError, Result};

const MAGIC: &[u8; 6] = b"SCSES1";
const HEADER_BYTES: usize = 6 + 2 + 24;

/// Encrypts serialized Telegram session state before it reaches the filesystem.
#[derive(Clone)]
pub struct SessionCipher {
    key: Zeroizing<[u8; 32]>,
    key_version: u16,
}

impl SessionCipher {
    pub fn from_hex(value: &str) -> Result<Self> {
        let decoded = hex::decode(value).map_err(|_| {
            CoreError::InvalidInput("SALVAGE_SESSION_KEY must be 32 bytes of hex".to_string())
        })?;
        let key: [u8; 32] = decoded.try_into().map_err(|_| {
            CoreError::InvalidInput("SALVAGE_SESSION_KEY must be 32 bytes of hex".to_string())
        })?;
        Ok(Self {
            key: Zeroizing::new(key),
            key_version: 1,
        })
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| CoreError::Internal("invalid session key".to_string()))?;
        let mut nonce = [0_u8; 24];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .map_err(|_| CoreError::Internal("session encryption failed".to_string()))?;
        let mut envelope = Vec::with_capacity(HEADER_BYTES + ciphertext.len());
        envelope.extend_from_slice(MAGIC);
        envelope.extend_from_slice(&self.key_version.to_le_bytes());
        envelope.extend_from_slice(&nonce);
        envelope.extend_from_slice(&ciphertext);
        Ok(envelope)
    }

    pub fn open(&self, envelope: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if envelope.len() < HEADER_BYTES + 16 || &envelope[..6] != MAGIC {
            return Err(CoreError::Unauthorized);
        }
        let version = u16::from_le_bytes([envelope[6], envelope[7]]);
        if version != self.key_version {
            return Err(CoreError::Unavailable(
                "session key version is not configured".to_string(),
            ));
        }
        let cipher = XChaCha20Poly1305::new_from_slice(self.key.as_slice())
            .map_err(|_| CoreError::Internal("invalid session key".to_string()))?;
        let plaintext = cipher
            .decrypt(XNonce::from_slice(&envelope[8..32]), &envelope[32..])
            .map_err(|_| CoreError::Unauthorized)?;
        Ok(Zeroizing::new(plaintext))
    }

    pub async fn save(&self, account_dir: &Path, plaintext: &[u8]) -> Result<()> {
        tokio::fs::create_dir_all(account_dir).await?;
        let envelope = self.seal(plaintext)?;
        let destination = session_path(account_dir);
        let temporary = account_dir.join("telegram.session.scse.tmp");
        write_private(&temporary, &envelope).await?;
        tokio::fs::rename(temporary, destination).await?;
        Ok(())
    }

    pub fn save_blocking(&self, account_dir: &Path, plaintext: &[u8]) -> Result<()> {
        std::fs::create_dir_all(account_dir)?;
        let envelope = self.seal(plaintext)?;
        let destination = session_path(account_dir);
        let temporary = account_dir.join("telegram.session.scse.tmp");
        write_private_blocking(&temporary, &envelope)?;
        std::fs::rename(temporary, destination)?;
        Ok(())
    }

    pub async fn load(&self, account_dir: &Path) -> Result<Option<Zeroizing<Vec<u8>>>> {
        match tokio::fs::read(session_path(account_dir)).await {
            Ok(bytes) => self.open(&bytes).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub async fn remove(&self, account_dir: &Path) -> Result<()> {
        match tokio::fs::remove_file(session_path(account_dir)).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
}

pub fn session_path(account_dir: &Path) -> PathBuf {
    account_dir.join("telegram.session.scse")
}

#[cfg(unix)]
fn write_private_blocking(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private_blocking(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(unix)]
async fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true).mode(0o600);
    let mut file = options.open(path).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, bytes).await?;
    file.sync_all().await?;
    Ok(())
}

#[cfg(not(unix))]
async fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    tokio::fs::write(path, bytes).await?;
    Ok(())
}
