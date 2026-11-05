use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Write as _;
use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use js_sys::{Array, Date, Reflect, Uint8Array};
use salvage_tdenc2::header::WRITER_CHUNK_SIZE;
use salvage_tdenc2::recovery::{open_recovery, seal_recovery};
use salvage_tdenc2::vault::{VaultPayload, VaultProfile, open_vault, seal_vault};
use salvage_tdenc2::{
    ChunkEncryptor, Credential, EncryptionSession, Header, ProtectedMetadata, decrypt_reader,
};
use sha2::{Digest, Sha256};
use wasm_bindgen::{JsCast, JsValue, closure::Closure};
use wasm_bindgen_futures::{JsFuture, spawn_local};
use web_sys::{
    AbortController, DedicatedWorkerGlobalScope, File, FilePropertyBag, FileSystemDirectoryHandle,
    MessageEvent, Request, RequestCredentials, RequestInit, Response, WorkerGlobalScope,
};
use zeroize::Zeroizing;

use crate::opfs::{create_opfs_file, remove_opfs_file, worker_opfs_root};
use crate::protocol::{
    Command, CredentialMode, JobRequest, JobResponse, JobResult, VaultInfo, WorkerError,
    WorkerResult,
};
use crate::storage;

const MAX_BASE64_PLAINTEXT_RECORD: usize = 1_398_108;

type SharedState = Rc<RefCell<WorkerState>>;

struct UnlockedVault {
    account_id: String,
    payload: VaultPayload,
}

struct StagedPrefix {
    expected_len: u64,
    hashed_len: u64,
    hash: Sha256,
}

impl StagedPrefix {
    fn new(header: &[u8], expected_len: u64) -> WorkerResult<Self> {
        if expected_len < header.len() as u64 {
            return Err(WorkerError::new(
                "staged ciphertext prefix is shorter than the complete header",
            ));
        }
        let mut hash = Sha256::new();
        hash.update(header);
        Ok(Self {
            expected_len,
            hashed_len: header.len() as u64,
            hash,
        })
    }

    fn update(&mut self, record: &[u8]) -> WorkerResult<()> {
        if self.hashed_len == self.expected_len {
            return Ok(());
        }
        let remaining = self.expected_len - self.hashed_len;
        let count = usize::try_from(remaining.min(record.len() as u64))
            .map_err(|_| WorkerError::new("staged prefix length overflow"))?;
        self.hash.update(&record[..count]);
        self.hashed_len = self
            .hashed_len
            .checked_add(count as u64)
            .ok_or_else(|| WorkerError::new("staged prefix length overflow"))?;
        Ok(())
    }

    fn digest(&self) -> WorkerResult<String> {
        if self.hashed_len != self.expected_len {
            return Err(WorkerError::new(
                "source replay did not reach the staged ciphertext prefix",
            ));
        }
        Ok(hex(&self.hash.clone().finalize()))
    }

    fn finish(self) -> WorkerResult<String> {
        if self.hashed_len != self.expected_len {
            return Err(WorkerError::new(
                "source replay did not reach the staged ciphertext prefix",
            ));
        }
        Ok(hex(&self.hash.finalize()))
    }
}

struct EncryptionJob {
    account_id: String,
    owner_job_id: String,
    generation: u64,
    session: EncryptionSession,
    encryptor: ChunkEncryptor,
    staged: Option<StagedPrefix>,
}

struct JobControl {
    account_id: Option<String>,
    generation: u64,
    cancelled: Rc<Cell<bool>>,
    abort: AbortController,
}

#[derive(Default)]
struct WorkerState {
    vault: Option<UnlockedVault>,
    sessions: HashMap<String, EncryptionJob>,
    jobs: HashMap<String, Rc<JobControl>>,
    generation: u64,
}

struct JobOutcome {
    result: JobResult,
    file: Option<File>,
}

impl From<JobResult> for JobOutcome {
    fn from(result: JobResult) -> Self {
        Self { result, file: None }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 15) as usize] as char);
    }
    output
}

fn random_hex() -> WorkerResult<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)
        .map_err(|_| WorkerError::new("secure browser randomness is unavailable"))?;
    Ok(hex(&bytes))
}

fn validate_account(account_id: &str) -> WorkerResult<()> {
    if account_id.is_empty() {
        Err(WorkerError::new("account ID must not be empty"))
    } else {
        Ok(())
    }
}

fn command_account(command: &Command) -> Option<String> {
    match command {
        Command::VaultCreate { account_id, .. }
        | Command::VaultOpen { account_id, .. }
        | Command::VaultUnlock { account_id, .. }
        | Command::VaultStatus { account_id }
        | Command::RecoveryExport { account_id, .. }
        | Command::RecoveryImport { account_id, .. }
        | Command::EncryptionStart { account_id, .. }
        | Command::EncryptionContinue { account_id, .. }
        | Command::EncryptionNext { account_id, .. }
        | Command::EncryptionCheckpoint { account_id, .. }
        | Command::EncryptionFinish { account_id, .. }
        | Command::EncryptionAbort { account_id, .. }
        | Command::DownloadDecrypt { account_id, .. }
        | Command::JournalLoad { account_id, .. }
        | Command::JournalList { account_id }
        | Command::JournalDelete { account_id, .. } => Some(account_id.clone()),
        Command::JournalSave { journal } => Some(journal.account_id.clone()),
        Command::Lock | Command::Cancel { .. } => None,
    }
}

fn ensure_active(state: &SharedState, control: &JobControl) -> WorkerResult<()> {
    if control.cancelled.get() || state.borrow().generation != control.generation {
        Err(WorkerError::new(
            "job was cancelled or its account was locked",
        ))
    } else {
        Ok(())
    }
}

fn credential(
    state: &SharedState,
    account_id: &str,
    mode: &CredentialMode,
) -> WorkerResult<Credential> {
    validate_account(account_id)?;
    match mode {
        CredentialMode::Passphrase { passphrase } => {
            if passphrase.expose().is_empty() {
                return Err(WorkerError::new("passphrase must not be empty"));
            }
            Ok(Credential::passphrase(passphrase.expose().as_bytes()))
        }
        CredentialMode::UnlockedVault => {
            let state = state.borrow();
            let vault = state
                .vault
                .as_ref()
                .filter(|vault| vault.account_id == account_id)
                .ok_or_else(|| WorkerError::new("the account vault is not unlocked"))?;
            Ok(Credential::vault_key(vault.payload.master_key))
        }
    }
}

fn vault_info(vault: &UnlockedVault, unlocked: bool) -> VaultInfo {
    VaultInfo {
        account_id: vault.account_id.clone(),
        unlocked,
        created_at: Some(vault.payload.created_at),
        profile_ids: vault
            .payload
            .profiles
            .iter()
            .map(|profile| profile.id.clone())
            .collect(),
    }
}

fn locked_vault_info(account_id: String) -> VaultInfo {
    VaultInfo {
        account_id,
        unlocked: false,
        created_at: None,
        profile_ids: Vec::new(),
    }
}

fn require_no_unlocked_vault(state: &SharedState) -> WorkerResult<()> {
    if state.borrow().vault.is_some() {
        Err(WorkerError::new(
            "lock the current vault before opening or creating another",
        ))
    } else {
        Ok(())
    }
}

fn validate_staged_boundary(
    header: &Header,
    header_len: usize,
    staged_len: u64,
) -> WorkerResult<()> {
    let mut offset = header_len as u64;
    if staged_len == offset {
        return Ok(());
    }
    let chunk_count = header.chunk_count()?;
    for index in 0..chunk_count {
        let plaintext_offset = u64::from(index) * u64::from(WRITER_CHUNK_SIZE);
        let plaintext_len =
            (header.total_plaintext_len - plaintext_offset).min(u64::from(WRITER_CHUNK_SIZE));
        offset = offset
            .checked_add(plaintext_len + 16)
            .ok_or_else(|| WorkerError::new("staged ciphertext length overflow"))?;
        if staged_len == offset {
            return Ok(());
        }
        if staged_len < offset {
            return Err(WorkerError::new(
                "staged ciphertext must end at a complete content-record boundary",
            ));
        }
    }
    Err(WorkerError::new(
        "staged ciphertext prefix is not a resumable content-record prefix",
    ))
}

#[allow(clippy::too_many_arguments)]
fn start_encryption(
    state: &SharedState,
    owner_job_id: &str,
    account_id: String,
    original_name: String,
    mime_type: String,
    total_plaintext_len: u64,
    credential_mode: &CredentialMode,
    continuation: Option<(String, u64)>,
) -> WorkerResult<JobResult> {
    validate_account(&account_id)?;
    let credential = credential(state, &account_id, credential_mode)?;
    let metadata = ProtectedMetadata::new(original_name, mime_type);
    let (session, staged_len, continuation) = if let Some((header, staged_len)) = continuation {
        let complete_header = BASE64
            .decode(header)
            .map_err(|_| WorkerError::new("complete header is not valid base64"))?;
        let session = EncryptionSession::from_header(
            &complete_header,
            total_plaintext_len,
            Some(&metadata),
            &[credential],
        )?;
        validate_staged_boundary(session.header(), complete_header.len(), staged_len)?;
        (session, Some(staged_len), true)
    } else {
        (
            EncryptionSession::new(total_plaintext_len, Some(metadata), &[credential])?,
            None,
            false,
        )
    };
    let session_id = hex(&session.header().uuid);
    if state.borrow().sessions.contains_key(&session_id) {
        return Err(WorkerError::new("encryption session ID collision"));
    }
    let staged = staged_len
        .map(|len| StagedPrefix::new(session.complete_header(), len))
        .transpose()?;
    let result = JobResult::EncryptionStarted {
        session_id: session_id.clone(),
        remote_name: format!("{session_id}.tdenc2"),
        complete_header: BASE64.encode(session.complete_header()),
        ciphertext_len: session.header().expected_ciphertext_len()?,
        plaintext_chunk_size: WRITER_CHUNK_SIZE,
        continuation,
        staged_ciphertext_len: staged_len,
    };
    let generation = state.borrow().generation;
    let encryptor = session.chunk_encryptor();
    state.borrow_mut().sessions.insert(
        session_id,
        EncryptionJob {
            account_id,
            owner_job_id: owner_job_id.to_owned(),
            generation,
            session,
            encryptor,
            staged,
        },
    );
    Ok(result)
}

fn encryption_next(
    state: &SharedState,
    account_id: &str,
    session_id: &str,
    plaintext: &str,
) -> WorkerResult<JobResult> {
    if plaintext.len() > MAX_BASE64_PLAINTEXT_RECORD {
        return Err(WorkerError::new("plaintext record exceeds 1 MiB"));
    }
    let plaintext = Zeroizing::new(
        BASE64
            .decode(plaintext)
            .map_err(|_| WorkerError::new("plaintext record is not valid base64"))?,
    );
    let mut state = state.borrow_mut();
    if state
        .sessions
        .get(session_id)
        .is_none_or(|job| job.account_id != account_id || job.generation != state.generation)
    {
        return Err(WorkerError::new(
            "encryption session is unavailable for this account",
        ));
    }
    let job = state
        .sessions
        .get_mut(session_id)
        .expect("session presence checked");
    let record_index = job.encryptor.next_index();
    let plaintext_offset = job.encryptor.plaintext_offset();
    let ciphertext_offset = job.session.complete_header().len() as u64
        + plaintext_offset
        + u64::from(record_index) * 16;
    let ciphertext = job.encryptor.encrypt_chunk(&plaintext)?;
    let next_plaintext_offset = job.encryptor.plaintext_offset();
    let next_ciphertext_offset = ciphertext_offset + ciphertext.len() as u64;
    if let Some(staged) = &mut job.staged {
        staged.update(&ciphertext)?;
    }
    Ok(JobResult::EncryptionRecord {
        session_id: session_id.to_owned(),
        record_index,
        plaintext_offset,
        next_plaintext_offset,
        ciphertext_offset,
        next_ciphertext_offset,
        ciphertext: BASE64.encode(ciphertext),
    })
}

fn encryption_checkpoint(
    state: &SharedState,
    account_id: &str,
    session_id: &str,
) -> WorkerResult<JobResult> {
    let state = state.borrow();
    let job = state
        .sessions
        .get(session_id)
        .filter(|job| job.account_id == account_id && job.generation == state.generation)
        .ok_or_else(|| WorkerError::new("encryption session is unavailable for this account"))?;
    let staged_ciphertext_sha256 = job.staged.as_ref().map(StagedPrefix::digest).transpose()?;
    Ok(JobResult::EncryptionCheckpoint {
        session_id: session_id.to_owned(),
        staged_ciphertext_sha256,
    })
}

fn encryption_finish(
    state: &SharedState,
    account_id: &str,
    session_id: &str,
) -> WorkerResult<JobResult> {
    let mut state = state.borrow_mut();
    if state
        .sessions
        .get(session_id)
        .is_none_or(|job| job.account_id != account_id || job.generation != state.generation)
    {
        return Err(WorkerError::new(
            "encryption session is unavailable for this account",
        ));
    }
    let job = state
        .sessions
        .remove(session_id)
        .expect("session presence checked");
    let ciphertext_offset = job.session.complete_header().len() as u64
        + job.encryptor.plaintext_offset()
        + u64::from(job.encryptor.next_index()) * 16;
    let ciphertext_len = job.session.header().expected_ciphertext_len()?;
    let staged = job.staged;
    let finished = job.encryptor.finalize()?;
    let staged_ciphertext_sha256 = staged.map(StagedPrefix::finish).transpose()?;
    Ok(JobResult::EncryptionFinished {
        session_id: session_id.to_owned(),
        ciphertext_offset,
        ciphertext_len,
        final_record: BASE64.encode(finished.record),
        plaintext_sha256: hex(&finished.summary.plaintext_sha256),
        staged_ciphertext_sha256,
    })
}

async fn download_decrypt(
    state: &SharedState,
    control: &Rc<JobControl>,
    account_id: &str,
    url: &str,
    expected_ciphertext_len: u64,
    credential_mode: &CredentialMode,
) -> WorkerResult<JobOutcome> {
    let credential = credential(state, account_id, credential_mode)?;
    let worker = js_sys::global()
        .dyn_into::<WorkerGlobalScope>()
        .map_err(|_| WorkerError::new("protected downloads require a Dedicated Worker"))?;
    let root = worker_opfs_root().await?;
    ensure_active(state, control)?;
    let ciphertext_name = format!("salvage-{}.tdenc2", random_hex()?);
    let plaintext_name = format!("salvage-{}.download", random_hex()?);

    let outcome = download_into_opfs(
        state,
        control,
        &worker,
        &root,
        &ciphertext_name,
        &plaintext_name,
        url,
        expected_ciphertext_len,
        credential,
    )
    .await;

    // The ciphertext is no longer needed. A successful plaintext File still
    // references its OPFS entry, so retain it until the page finishes reading it.
    remove_opfs_file(&root, &ciphertext_name).await?;
    if outcome.is_err() {
        remove_opfs_file(&root, &plaintext_name).await?;
    }
    ensure_active(state, control)?;
    outcome
}

#[allow(clippy::too_many_arguments)]
async fn download_into_opfs(
    state: &SharedState,
    control: &Rc<JobControl>,
    worker: &WorkerGlobalScope,
    root: &FileSystemDirectoryHandle,
    ciphertext_name: &str,
    plaintext_name: &str,
    url: &str,
    expected_ciphertext_len: u64,
    credential: Credential,
) -> WorkerResult<JobOutcome> {
    let (ciphertext_file, mut ciphertext) = create_opfs_file(root, ciphertext_name).await?;
    ensure_active(state, control)?;
    let (plaintext_file, mut plaintext) = create_opfs_file(root, plaintext_name).await?;
    ensure_active(state, control)?;

    let init = RequestInit::new();
    init.set_method("GET");
    init.set_credentials(RequestCredentials::Include);
    init.set_signal(Some(&control.abort.signal()));
    let request = Request::new_with_str_and_init(url, &init)
        .map_err(|_| WorkerError::new("could not create the protected download request"))?;
    let response = JsFuture::from(worker.fetch_with_request(&request))
        .await
        .map_err(|_| WorkerError::new("protected download request failed"))?;
    ensure_active(state, control)?;
    let response = response
        .dyn_into::<Response>()
        .map_err(|_| WorkerError::new("browser returned an invalid download response"))?;
    if !response.ok() {
        return Err(WorkerError::new(format!(
            "protected download returned HTTP {}",
            response.status()
        )));
    }
    let body = response
        .body()
        .ok_or_else(|| WorkerError::new("protected download response has no body"))?;
    let reader = web_sys::ReadableStreamDefaultReader::new(&body)
        .map_err(|_| WorkerError::new("could not read the protected download stream"))?;
    let mut downloaded = 0_u64;
    loop {
        let value = JsFuture::from(reader.read())
            .await
            .map_err(|_| WorkerError::new("protected download stream failed"))?;
        ensure_active(state, control)?;
        let done = Reflect::get(&value, &JsValue::from_str("done"))
            .ok()
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        if done {
            break;
        }
        let value = Reflect::get(&value, &JsValue::from_str("value"))
            .map_err(|_| WorkerError::new("download stream chunk is missing"))?
            .dyn_into::<Uint8Array>()
            .map_err(|_| WorkerError::new("download stream chunk is not binary"))?;
        downloaded = downloaded
            .checked_add(u64::from(value.length()))
            .ok_or_else(|| WorkerError::new("ciphertext length overflow"))?;
        if downloaded > expected_ciphertext_len {
            return Err(WorkerError::new(
                "download exceeds the expected ciphertext length",
            ));
        }
        ciphertext.write_js_array(&value)?;
    }
    reader.release_lock();
    if downloaded != expected_ciphertext_len {
        return Err(WorkerError::new(
            "download length does not match the expected ciphertext length",
        ));
    }
    ciphertext.flush()?;
    ensure_active(state, control)?;

    // decrypt_reader performs its complete authentication pass before publishing any plaintext.
    let decrypted = decrypt_reader(&mut ciphertext, &mut plaintext, &[credential])?;
    plaintext.flush()?;
    drop(ciphertext);
    drop(plaintext);
    ensure_active(state, control)?;

    let metadata = decrypted.metadata;
    let original_name = metadata
        .as_ref()
        .map(|metadata| sanitize_download_name(&metadata.original_name))
        .unwrap_or_else(|| "download".to_owned());
    let mime_type = metadata
        .as_ref()
        .map(|metadata| metadata.mime_type.clone())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_owned());
    let plaintext_file = JsFuture::from(plaintext_file.get_file())
        .await
        .map_err(|_| WorkerError::new("could not publish the verified plaintext File"))?
        .dyn_into::<File>()
        .map_err(|_| WorkerError::new("browser returned an invalid plaintext File"))?;
    ensure_active(state, control)?;
    let parts = Array::new();
    parts.push(&plaintext_file);
    let options = FilePropertyBag::new();
    options.set_type(&mime_type);
    options.set_last_modified(Date::now());
    let file = File::new_with_blob_sequence_and_options(&parts, &original_name, &options)
        .map_err(|_| WorkerError::new("could not name the verified plaintext File"))?;
    drop(ciphertext_file);
    Ok(JobOutcome {
        result: JobResult::Downloaded {
            original_name,
            mime_type,
            plaintext_len: decrypted.summary.plaintext_len,
            plaintext_sha256: hex(&decrypted.summary.plaintext_sha256),
        },
        file: Some(file),
    })
}

/// Reduces authenticated metadata to a safe download basename; sync_path is never consulted.
pub fn sanitize_download_name(name: &str) -> String {
    let basename = name.rsplit(['/', '\\']).next().unwrap_or_default().trim();
    let sanitized: String = basename
        .chars()
        .map(|character| {
            if character.is_control() || character == '\0' {
                '_'
            } else {
                character
            }
        })
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.is_empty() || sanitized == "." || sanitized == ".." {
        return "download".to_owned();
    }
    if sanitized.len() <= 255 {
        return sanitized.to_owned();
    }
    let mut boundary = 255;
    while !sanitized.is_char_boundary(boundary) {
        boundary -= 1;
    }
    sanitized[..boundary].to_owned()
}

async fn dispatch(
    state: SharedState,
    job_id: String,
    control: Rc<JobControl>,
    command: Command,
) -> WorkerResult<JobOutcome> {
    ensure_active(&state, &control)?;
    match command {
        Command::VaultCreate {
            account_id,
            passphrase,
            profile_ids,
        } => {
            validate_account(&account_id)?;
            require_no_unlocked_vault(&state)?;
            if passphrase.expose().is_empty() {
                return Err(WorkerError::new("passphrase must not be empty"));
            }
            if storage::load_vault_container(&account_id).await?.is_some() {
                return Err(WorkerError::new(
                    "an encrypted vault already exists for this account",
                ));
            }
            ensure_active(&state, &control)?;
            let mut master_key = Zeroizing::new([0_u8; 32]);
            getrandom::fill(master_key.as_mut())
                .map_err(|_| WorkerError::new("secure browser randomness is unavailable"))?;
            let mut profiles = Vec::with_capacity(profile_ids.len());
            for id in profile_ids {
                let mut key = Zeroizing::new([0_u8; 32]);
                getrandom::fill(key.as_mut())
                    .map_err(|_| WorkerError::new("secure browser randomness is unavailable"))?;
                profiles.push(VaultProfile::new(id, *key)?);
            }
            let payload = VaultPayload::new((Date::now() / 1000.0) as i64, *master_key, profiles)?;
            let container = seal_vault(&payload, passphrase.expose().as_bytes())?;
            storage::store_vault_container(&account_id, &container).await?;
            ensure_active(&state, &control)?;
            let vault = UnlockedVault {
                account_id,
                payload,
            };
            let info = vault_info(&vault, true);
            state.borrow_mut().vault = Some(vault);
            Ok(JobResult::VaultCreated {
                vault: info,
                container: BASE64.encode(container),
            }
            .into())
        }
        Command::VaultOpen {
            account_id,
            container,
            passphrase,
        } => {
            validate_account(&account_id)?;
            require_no_unlocked_vault(&state)?;
            let container = BASE64
                .decode(container)
                .map_err(|_| WorkerError::new("vault container is not valid base64"))?;
            let payload = open_vault(&container, passphrase.expose().as_bytes())?;
            storage::store_vault_container(&account_id, &container).await?;
            ensure_active(&state, &control)?;
            let vault = UnlockedVault {
                account_id,
                payload,
            };
            let info = vault_info(&vault, true);
            state.borrow_mut().vault = Some(vault);
            Ok(JobResult::Vault { vault: info }.into())
        }
        Command::VaultUnlock {
            account_id,
            passphrase,
        } => {
            validate_account(&account_id)?;
            require_no_unlocked_vault(&state)?;
            let container = storage::load_vault_container(&account_id)
                .await?
                .ok_or_else(|| WorkerError::new("no encrypted vault exists for this account"))?;
            ensure_active(&state, &control)?;
            let payload = open_vault(&container, passphrase.expose().as_bytes())?;
            let vault = UnlockedVault {
                account_id,
                payload,
            };
            let info = vault_info(&vault, true);
            state.borrow_mut().vault = Some(vault);
            Ok(JobResult::Vault { vault: info }.into())
        }
        Command::VaultStatus { account_id } => {
            validate_account(&account_id)?;
            let state = state.borrow();
            let info = state
                .vault
                .as_ref()
                .filter(|vault| vault.account_id == account_id)
                .map(|vault| vault_info(vault, true))
                .unwrap_or_else(|| locked_vault_info(account_id));
            Ok(JobResult::Vault { vault: info }.into())
        }
        Command::RecoveryExport {
            account_id,
            passphrase,
        } => {
            if passphrase.expose().is_empty() {
                return Err(WorkerError::new("passphrase must not be empty"));
            }
            let state = state.borrow();
            let vault = state
                .vault
                .as_ref()
                .filter(|vault| vault.account_id == account_id)
                .ok_or_else(|| WorkerError::new("the account vault is not unlocked"))?;
            let container = seal_recovery(&vault.payload, passphrase.expose().as_bytes())?;
            Ok(JobResult::RecoveryExported {
                container: BASE64.encode(container),
            }
            .into())
        }
        Command::RecoveryImport {
            account_id,
            container,
            recovery_passphrase,
            vault_passphrase,
            replace_existing,
        } => {
            validate_account(&account_id)?;
            require_no_unlocked_vault(&state)?;
            if vault_passphrase.expose().is_empty() {
                return Err(WorkerError::new("vault passphrase must not be empty"));
            }
            let existing = storage::load_vault_container(&account_id).await?;
            ensure_active(&state, &control)?;
            if existing.is_some() && !replace_existing {
                return Err(WorkerError::new(
                    "vault replacement requires replaceExisting=true",
                ));
            }
            let container = BASE64
                .decode(container)
                .map_err(|_| WorkerError::new("recovery container is not valid base64"))?;
            let payload = open_recovery(&container, recovery_passphrase.expose().as_bytes())?;
            let vault_container = seal_vault(&payload, vault_passphrase.expose().as_bytes())?;
            storage::store_vault_container(&account_id, &vault_container).await?;
            ensure_active(&state, &control)?;
            let vault = UnlockedVault {
                account_id,
                payload,
            };
            let info = vault_info(&vault, true);
            state.borrow_mut().vault = Some(vault);
            Ok(JobResult::Vault { vault: info }.into())
        }
        Command::EncryptionStart {
            account_id,
            original_name,
            mime_type,
            total_plaintext_len,
            credential,
        } => Ok(start_encryption(
            &state,
            &job_id,
            account_id,
            original_name,
            mime_type,
            total_plaintext_len,
            &credential,
            None,
        )?
        .into()),
        Command::EncryptionContinue {
            account_id,
            original_name,
            mime_type,
            total_plaintext_len,
            complete_header,
            staged_ciphertext_len,
            credential,
        } => Ok(start_encryption(
            &state,
            &job_id,
            account_id,
            original_name,
            mime_type,
            total_plaintext_len,
            &credential,
            Some((complete_header, staged_ciphertext_len)),
        )?
        .into()),
        Command::EncryptionNext {
            account_id,
            session_id,
            plaintext,
        } => Ok(encryption_next(&state, &account_id, &session_id, plaintext.expose())?.into()),
        Command::EncryptionCheckpoint {
            account_id,
            session_id,
        } => Ok(encryption_checkpoint(&state, &account_id, &session_id)?.into()),
        Command::EncryptionFinish {
            account_id,
            session_id,
        } => Ok(encryption_finish(&state, &account_id, &session_id)?.into()),
        Command::EncryptionAbort {
            account_id,
            session_id,
        } => {
            let mut state = state.borrow_mut();
            let matches = state
                .sessions
                .get(&session_id)
                .is_some_and(|job| job.account_id == account_id);
            if matches {
                state.sessions.remove(&session_id);
            }
            Ok(JobResult::Ack {
                operation: "encryptionAbort".to_owned(),
            }
            .into())
        }
        Command::DownloadDecrypt {
            account_id,
            url,
            expected_ciphertext_len,
            credential,
        } => {
            download_decrypt(
                &state,
                &control,
                &account_id,
                &url,
                expected_ciphertext_len,
                &credential,
            )
            .await
        }
        Command::JournalSave { journal } => {
            storage::save_journal(&journal).await?;
            ensure_active(&state, &control)?;
            Ok(JobResult::Ack {
                operation: "journalSave".to_owned(),
            }
            .into())
        }
        Command::JournalLoad {
            account_id,
            original_id,
        } => {
            let journal = storage::load_journal(&account_id, &original_id).await?;
            ensure_active(&state, &control)?;
            Ok(JobResult::Journal { journal }.into())
        }
        Command::JournalList { account_id } => {
            let journals = storage::list_journals(&account_id).await?;
            ensure_active(&state, &control)?;
            Ok(JobResult::Journals { journals }.into())
        }
        Command::JournalDelete {
            account_id,
            original_id,
        } => {
            storage::delete_journal(&account_id, &original_id).await?;
            ensure_active(&state, &control)?;
            Ok(JobResult::Ack {
                operation: "journalDelete".to_owned(),
            }
            .into())
        }
        Command::Lock | Command::Cancel { .. } => Err(WorkerError::new(
            "lock and cancel must be handled as control jobs",
        )),
    }
}

fn lock_state(state: &SharedState) {
    let mut state = state.borrow_mut();
    state.generation = state.generation.wrapping_add(1);
    state.sessions.clear();
    for control in state.jobs.values() {
        control.cancelled.set(true);
        control.abort.abort();
    }
    state.jobs.clear();
    state.vault.take();
}

fn cancel(
    state: &SharedState,
    account_id: Option<String>,
    job_id: Option<String>,
) -> WorkerResult<()> {
    let mut state = state.borrow_mut();
    match (account_id, job_id) {
        (Some(account_id), None) => {
            validate_account(&account_id)?;
            state.sessions.retain(|_, job| job.account_id != account_id);
            let jobs: Vec<String> = state
                .jobs
                .iter()
                .filter(|(_, control)| control.account_id.as_deref() == Some(&account_id))
                .map(|(id, _)| id.clone())
                .collect();
            for id in jobs {
                if let Some(control) = state.jobs.remove(&id) {
                    control.cancelled.set(true);
                    control.abort.abort();
                }
            }
            Ok(())
        }
        (None, Some(job_id)) => {
            state.sessions.retain(|_, job| job.owner_job_id != job_id);
            if let Some(control) = state.jobs.remove(&job_id) {
                control.cancelled.set(true);
                control.abort.abort();
            }
            Ok(())
        }
        _ => Err(WorkerError::new(
            "cancel requires exactly one of accountId or jobId",
        )),
    }
}

fn post_response(scope: &DedicatedWorkerGlobalScope, response: JobResponse, file: Option<File>) {
    match serde_wasm_bindgen::to_value(&response) {
        Ok(value) => {
            if let Some(file) = file {
                let _ = Reflect::set(&value, &JsValue::from_str("file"), &file);
            }
            let _ = scope.post_message(&value);
        }
        Err(_) => {
            let fallback =
                JobResponse::failure(response.job_id, "could not serialize worker result");
            if let Ok(value) = serde_json::to_string(&fallback) {
                let _ = scope.post_message(&JsValue::from_str(&value));
            }
        }
    }
}

fn run_request(scope: DedicatedWorkerGlobalScope, state: SharedState, request: JobRequest) {
    if request.job_id.is_empty() {
        post_response(
            &scope,
            JobResponse::failure(request.job_id, "job ID must not be empty"),
            None,
        );
        return;
    }
    match request.command {
        Command::Lock => {
            lock_state(&state);
            post_response(
                &scope,
                JobResponse::success(
                    request.job_id,
                    JobResult::Ack {
                        operation: "lock".to_owned(),
                    },
                ),
                None,
            );
        }
        Command::Cancel { account_id, job_id } => {
            let response = match cancel(&state, account_id, job_id) {
                Ok(()) => JobResponse::success(
                    request.job_id,
                    JobResult::Ack {
                        operation: "cancel".to_owned(),
                    },
                ),
                Err(error) => JobResponse::failure(request.job_id, error.to_string()),
            };
            post_response(&scope, response, None);
        }
        command => {
            let account_id = command_account(&command);
            let control = Rc::new(JobControl {
                account_id,
                generation: state.borrow().generation,
                cancelled: Rc::new(Cell::new(false)),
                abort: AbortController::new().expect("AbortController is available in Workers"),
            });
            if state.borrow().jobs.contains_key(&request.job_id) {
                post_response(
                    &scope,
                    JobResponse::failure(request.job_id, "job ID is already active"),
                    None,
                );
                return;
            }
            state
                .borrow_mut()
                .jobs
                .insert(request.job_id.clone(), control.clone());
            let job_id = request.job_id;
            let completion_id = job_id.clone();
            spawn_local(async move {
                let outcome =
                    dispatch(state.clone(), job_id.clone(), control.clone(), command).await;
                let is_current_job = state
                    .borrow()
                    .jobs
                    .get(&completion_id)
                    .is_some_and(|current| Rc::ptr_eq(current, &control));
                if is_current_job {
                    state.borrow_mut().jobs.remove(&completion_id);
                }
                match outcome {
                    Ok(outcome) => post_response(
                        &scope,
                        JobResponse::success(job_id, outcome.result),
                        outcome.file,
                    ),
                    Err(error) => post_response(
                        &scope,
                        JobResponse::failure(job_id, error.to_string()),
                        None,
                    ),
                }
            });
        }
    }
}

/// Registers the Dedicated Worker `onmessage` handler. This is the worker binary's only entry.
pub fn start_worker() {
    let scope = js_sys::global()
        .dyn_into::<DedicatedWorkerGlobalScope>()
        .expect("salvage-crypto-worker must run in a DedicatedWorkerGlobalScope");
    let state = Rc::new(RefCell::new(WorkerState::default()));
    let handler_scope = scope.clone();
    let handler = Closure::wrap(Box::new(move |event: MessageEvent| {
        let raw = Zeroizing::new(match event.data().as_string() {
            Some(raw) => raw,
            None => {
                post_response(
                    &handler_scope,
                    JobResponse::failure("unknown".to_owned(), "job request must be a JSON string"),
                    None,
                );
                return;
            }
        });
        match serde_json::from_str::<JobRequest>(&raw) {
            Ok(request) => run_request(handler_scope.clone(), state.clone(), request),
            Err(error) => post_response(
                &handler_scope,
                JobResponse::failure(
                    "unknown".to_owned(),
                    format!("invalid job request: {error}"),
                ),
                None,
            ),
        }
    }) as Box<dyn FnMut(MessageEvent)>);
    scope.set_onmessage(Some(handler.as_ref().unchecked_ref()));
    handler.forget();
    scope
        .post_message(&JsValue::from_str(crate::WORKER_READY_MESSAGE))
        .expect("post encryption Worker ready message");
}
