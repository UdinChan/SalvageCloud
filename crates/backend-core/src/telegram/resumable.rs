use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::RwLock,
    time::{Duration, Instant},
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use grammers_client::{Client, types::media::Uploaded};
use grammers_tl_types as tl;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};

use crate::{CoreError, Result};

const PART_BYTES: usize = 512 * 1024;
const RESUMABLE_FROM_BYTES: u64 = 10 * 1024 * 1024;
const WORKERS: usize = 4;
const MAX_AGE: Duration = Duration::from_secs(12 * 60 * 60);

#[derive(Default)]
pub struct ResumableUploads {
    root: RwLock<Option<PathBuf>>,
    records: Mutex<HashMap<String, UploadRecord>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UploadRecord {
    file_id: i64,
    source_sha256: String,
    source_bytes: u64,
    total_parts: i32,
    completed_parts: i32,
    prefix_sha256: String,
    created_unix: i64,
}

pub struct PreparedUpload {
    pub uploaded: Uploaded,
    pub key: String,
}

impl ResumableUploads {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bind(&self, account_dir: &Path) -> Result<()> {
        let root = account_dir.to_path_buf();
        let path = journal_path(&root);
        let records = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| CoreError::Internal(error.to_string()))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error.into()),
        };
        *self
            .records
            .try_lock()
            .map_err(|_| CoreError::Conflict("upload journal is busy".to_string()))? = records;
        *self.root.write().expect("upload journal root") = Some(root);
        Ok(())
    }

    pub async fn prepare(
        &self,
        client: &Client,
        source: &Path,
        name: &str,
        folder_id: Option<&str>,
    ) -> Result<Option<PreparedUpload>> {
        let source_bytes = tokio::fs::metadata(source).await?.len();
        if source_bytes < RESUMABLE_FROM_BYTES {
            return Ok(None);
        }
        let source_sha256 = hash_file(source, None).await?;
        let key = Sha256::digest(
            format!("{}:{name}:{source_sha256}", folder_id.unwrap_or("root")).as_bytes(),
        );
        let key = hex::encode(key);
        let mut records = self.records.lock().await;
        let now = chrono::Utc::now().timestamp();
        let mut record = records.get(&key).cloned().filter(|record| {
            record.source_sha256 == source_sha256
                && record.source_bytes == source_bytes
                && now.saturating_sub(record.created_unix) < MAX_AGE.as_secs() as i64
        });
        let mut prefix_hasher = Sha256::new();
        if let Some(existing) = &record {
            let prefix_bytes = existing.completed_parts as u64 * PART_BYTES as u64;
            let (actual, hasher) = hash_file_state(source, Some(prefix_bytes)).await?;
            if actual != existing.prefix_sha256 {
                record = None;
            } else {
                prefix_hasher = hasher;
            }
        }
        let mut record = record.unwrap_or_else(|| UploadRecord {
            file_id: fresh_file_id(),
            source_sha256,
            source_bytes,
            total_parts: source_bytes.div_ceil(PART_BYTES as u64) as i32,
            completed_parts: 0,
            prefix_sha256: hex::encode(Sha256::digest([])),
            created_unix: now,
        });
        records.insert(key.clone(), record.clone());
        self.persist(&records)?;

        let mut pending = FuturesUnordered::new();
        let mut completed_results = BTreeMap::new();
        let mut next_part = record.completed_parts;
        let mut last_checkpoint = Instant::now();
        while record.completed_parts < record.total_parts {
            while pending.len() < WORKERS && next_part < record.total_parts {
                let part = next_part;
                next_part += 1;
                let client = client.clone();
                let source = source.to_path_buf();
                let file_id = record.file_id;
                let total_parts = record.total_parts;
                pending.push(async move {
                    let result = save_part(&client, &source, file_id, total_parts, part).await;
                    (part, result)
                });
            }
            let Some((part, result)) = pending.next().await else {
                return Err(CoreError::Unavailable(
                    "Telegram upload made no progress".to_string(),
                ));
            };
            let bytes = result?;
            completed_results.insert(part, bytes);
            while let Some(bytes) = completed_results.remove(&record.completed_parts) {
                prefix_hasher.update(&bytes);
                record.completed_parts += 1;
                record.prefix_sha256 = hex::encode(prefix_hasher.clone().finalize());
            }
            if last_checkpoint.elapsed() >= Duration::from_secs(1) {
                records.insert(key.clone(), record.clone());
                self.persist(&records)?;
                last_checkpoint = Instant::now();
            }
        }
        records.insert(key.clone(), record.clone());
        self.persist(&records)?;
        Ok(Some(PreparedUpload {
            uploaded: Uploaded::from_raw(
                tl::types::InputFileBig {
                    id: record.file_id,
                    parts: record.total_parts,
                    name: name.to_string(),
                }
                .into(),
            ),
            key,
        }))
    }

    pub async fn finish(&self, key: &str) -> Result<()> {
        let mut records = self.records.lock().await;
        records.remove(key);
        self.persist(&records)
    }

    fn persist(&self, records: &HashMap<String, UploadRecord>) -> Result<()> {
        let root = self
            .root
            .read()
            .expect("upload journal root")
            .clone()
            .ok_or_else(|| {
                CoreError::Conflict(
                    "large uploads require an initialized account workspace".to_string(),
                )
            })?;
        let path = journal_path(&root);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = path.with_extension("json.tmp");
        let bytes =
            serde_json::to_vec(records).map_err(|error| CoreError::Internal(error.to_string()))?;
        write_private(&temporary, &bytes)?;
        std::fs::rename(temporary, path)?;
        Ok(())
    }
}

async fn save_part(
    client: &Client,
    source: &Path,
    file_id: i64,
    total_parts: i32,
    part: i32,
) -> Result<Vec<u8>> {
    let offset = part as u64 * PART_BYTES as u64;
    let mut file = tokio::fs::File::open(source).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut bytes = vec![0_u8; PART_BYTES];
    let mut read = 0;
    while read < bytes.len() {
        let count = file.read(&mut bytes[read..]).await?;
        if count == 0 {
            break;
        }
        read += count;
    }
    bytes.truncate(read);
    let stored = client
        .invoke(&tl::functions::upload::SaveBigFilePart {
            file_id,
            file_part: part,
            file_total_parts: total_parts,
            bytes: bytes.clone(),
        })
        .await
        .map_err(|_| {
            CoreError::Unavailable("Telegram did not store an uploaded file part".to_string())
        })?;
    if !stored {
        return Err(CoreError::Unavailable(
            "Telegram rejected an uploaded file part".to_string(),
        ));
    }
    Ok(bytes)
}

async fn hash_file(source: &Path, limit: Option<u64>) -> Result<String> {
    hash_file_state(source, limit)
        .await
        .map(|(digest, _)| digest)
}

async fn hash_file_state(source: &Path, limit: Option<u64>) -> Result<(String, Sha256)> {
    let mut file = tokio::fs::File::open(source).await?;
    let mut hasher = Sha256::new();
    let mut remaining = limit.unwrap_or(u64::MAX);
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining > 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let read = file.read(&mut buffer[..wanted]).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok((hex::encode(hasher.clone().finalize()), hasher))
}

fn fresh_file_id() -> i64 {
    let value = rand::random::<i64>() & 0x7fff_ffff_ffff_ffff;
    if value == 0 { 1 } else { value }
}

fn journal_path(root: &Path) -> PathBuf {
    root.join("large-uploads.json")
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
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
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes)?;
    Ok(())
}
