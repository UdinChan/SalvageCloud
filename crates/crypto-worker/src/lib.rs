#![forbid(unsafe_code)]
//! Dedicated Rust/WASM Worker for TDENC2 encryption, TDVLT2 vaults, and TDREC2 recovery.
//!
//! Requests are JSON strings containing `JobRequest`; responses are structured-cloneable
//! `JobResponse` objects. A successful protected download also has a top-level `file` property.
//! The page can instead use `WorkerClient`, which exposes the same typed protocol asynchronously.

mod protocol;

pub use protocol::{
    Command, ContinuationJournal, CredentialMode, JobRequest, JobResponse, JobResult, SecretString,
    VaultInfo, WORKER_READY_MESSAGE, WorkerError, WorkerResult,
};

#[cfg(target_arch = "wasm32")]
mod client;
#[cfg(target_arch = "wasm32")]
mod opfs;
#[cfg(target_arch = "wasm32")]
mod storage;
#[cfg(target_arch = "wasm32")]
mod worker;

#[cfg(target_arch = "wasm32")]
pub use client::{JobSuccess, WorkerClient};
#[cfg(target_arch = "wasm32")]
pub use opfs::OpfsFile;
#[cfg(target_arch = "wasm32")]
pub use storage::{
    delete_journal, delete_vault_container, list_journals, load_journal, load_vault_container,
    save_journal, store_vault_container,
};
#[cfg(target_arch = "wasm32")]
pub use worker::{sanitize_download_name, start_worker};
