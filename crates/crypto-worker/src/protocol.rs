use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub const WORKER_READY_MESSAGE: &str = "salvage-crypto-worker-ready-v1";

/// A passphrase whose Rust allocation is erased when the request or credential is dropped.
/// Browser JavaScript strings cannot be zeroized and should have the shortest possible lifetime.
#[derive(Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecretString(String);

impl SecretString {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl From<String> for SecretString {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for SecretString {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[redacted]")
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase")]
pub enum CredentialMode {
    Passphrase { passphrase: SecretString },
    UnlockedVault,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct JobRequest {
    pub job_id: String,
    pub command: Command,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "camelCase")]
pub enum Command {
    VaultCreate {
        account_id: String,
        passphrase: SecretString,
        #[serde(default)]
        profile_ids: Vec<String>,
    },
    /// Opens and persists an encrypted TDVLT2 container supplied by the page.
    VaultOpen {
        account_id: String,
        container: String,
        passphrase: SecretString,
    },
    /// Loads the account's encrypted TDVLT2 container from IndexedDB and unlocks it.
    VaultUnlock {
        account_id: String,
        passphrase: SecretString,
    },
    VaultStatus {
        account_id: String,
    },
    /// Locks every account, aborts jobs, and drops all unlocked keys and encryption sessions.
    Lock,
    /// Cancel either one job (including sessions it created) or every job for one account.
    Cancel {
        #[serde(default)]
        account_id: Option<String>,
        #[serde(default)]
        job_id: Option<String>,
    },
    RecoveryExport {
        account_id: String,
        passphrase: SecretString,
    },
    RecoveryImport {
        account_id: String,
        container: String,
        recovery_passphrase: SecretString,
        vault_passphrase: SecretString,
        #[serde(default)]
        replace_existing: bool,
    },
    EncryptionStart {
        account_id: String,
        original_name: String,
        mime_type: String,
        total_plaintext_len: u64,
        credential: CredentialMode,
    },
    /// Replays an unchanged source with its authenticated original header.
    /// `staged_ciphertext_len` must end at the header or a complete content-record boundary.
    EncryptionContinue {
        account_id: String,
        original_name: String,
        mime_type: String,
        total_plaintext_len: u64,
        complete_header: String,
        staged_ciphertext_len: u64,
        credential: CredentialMode,
    },
    /// Encrypts the next sequential 1 MiB (or final short) plaintext record.
    EncryptionNext {
        account_id: String,
        session_id: String,
        plaintext: SecretString,
    },
    EncryptionCheckpoint {
        account_id: String,
        session_id: String,
    },
    EncryptionFinish {
        account_id: String,
        session_id: String,
    },
    EncryptionAbort {
        account_id: String,
        session_id: String,
    },
    /// Streams a URL to OPFS and returns a File only after TDENC2 final verification.
    DownloadDecrypt {
        account_id: String,
        url: String,
        expected_ciphertext_len: u64,
        credential: CredentialMode,
    },
    JournalSave {
        journal: ContinuationJournal,
    },
    JournalLoad {
        account_id: String,
        original_id: String,
    },
    JournalList {
        account_id: String,
    },
    JournalDelete {
        account_id: String,
        original_id: String,
    },
}

/// Nonsecret resume state. Deliberately has no name, MIME, passphrase, key, or plaintext fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ContinuationJournal {
    pub account_id: String,
    pub original_id: String,
    pub remote_id: String,
    #[serde(default)]
    pub bot_id: Option<String>,
    pub complete_header: String,
    pub next_offset: u64,
    #[serde(default)]
    pub source_sha256: Option<String>,
    #[serde(default)]
    pub staged_ciphertext_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub account_id: String,
    pub unlocked: bool,
    pub created_at: Option<i64>,
    pub profile_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "camelCase")]
pub enum JobResult {
    Ack {
        operation: String,
    },
    Vault {
        vault: VaultInfo,
    },
    VaultCreated {
        vault: VaultInfo,
        /// The encrypted TDVLT2 container, encoded as standard base64.
        container: String,
    },
    RecoveryExported {
        /// The encrypted TDREC2 container, encoded as standard base64.
        container: String,
    },
    EncryptionStarted {
        session_id: String,
        remote_name: String,
        complete_header: String,
        ciphertext_len: u64,
        plaintext_chunk_size: u32,
        continuation: bool,
        staged_ciphertext_len: Option<u64>,
    },
    EncryptionRecord {
        session_id: String,
        record_index: u32,
        plaintext_offset: u64,
        next_plaintext_offset: u64,
        ciphertext_offset: u64,
        next_ciphertext_offset: u64,
        ciphertext: String,
    },
    EncryptionCheckpoint {
        session_id: String,
        staged_ciphertext_sha256: Option<String>,
    },
    EncryptionFinished {
        session_id: String,
        final_record: String,
        ciphertext_offset: u64,
        ciphertext_len: u64,
        plaintext_sha256: String,
        staged_ciphertext_sha256: Option<String>,
    },
    Downloaded {
        original_name: String,
        mime_type: String,
        plaintext_len: u64,
        plaintext_sha256: String,
    },
    Journal {
        journal: Option<ContinuationJournal>,
    },
    Journals {
        journals: Vec<ContinuationJournal>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobResponse {
    pub job_id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl JobResponse {
    pub fn success(job_id: String, result: JobResult) -> Self {
        Self {
            job_id,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn failure(job_id: String, error: impl Into<String>) -> Self {
        Self {
            job_id,
            ok: false,
            result: None,
            error: Some(error.into()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct WorkerError(pub String);

impl WorkerError {
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl std::fmt::Display for WorkerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WorkerError {}

impl From<salvage_tdenc2::Error> for WorkerError {
    fn from(value: salvage_tdenc2::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<std::io::Error> for WorkerError {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

impl From<serde_json::Error> for WorkerError {
    fn from(value: serde_json::Error) -> Self {
        Self(value.to_string())
    }
}

pub type WorkerResult<T> = Result<T, WorkerError>;
