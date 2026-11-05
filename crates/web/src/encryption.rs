use std::cell::RefCell;
use std::collections::HashSet;

use leptos::prelude::*;
use leptos::task::spawn_local;
use salvage_crypto_worker::{Command, JobSuccess, VaultInfo, WorkerClient};
use serde::Deserialize;
use uuid::Uuid;
use wasm_bindgen::JsCast;
use web_sys::{File, HtmlElement, Url};

#[derive(Clone)]
pub enum EncryptionWorkerStatus {
    Loading,
    Ready,
    Unavailable(String),
}

#[derive(Clone, Copy)]
pub struct EncryptionContext {
    status: RwSignal<EncryptionWorkerStatus>,
    worker_url: RwSignal<Option<String>>,
    account: RwSignal<Option<String>>,
    generation: RwSignal<u64>,
    vault: RwSignal<Option<VaultInfo>>,
}

#[derive(Default)]
struct WorkerSynchronization {
    account_id: Option<String>,
    session_generation: u64,
}

thread_local! {
    static CLIENT: RefCell<Option<WorkerClient>> = const { RefCell::new(None) };
    static SYNCHRONIZATION: RefCell<WorkerSynchronization> = RefCell::new(WorkerSynchronization::default());
    static OBJECT_URLS: RefCell<HashSet<String>> = RefCell::new(HashSet::new());
}

#[derive(Deserialize)]
struct WorkerManifest {
    #[serde(rename = "workerUrl")]
    worker_url: String,
}

impl EncryptionContext {
    pub fn new() -> Self {
        Self {
            status: RwSignal::new(EncryptionWorkerStatus::Loading),
            worker_url: RwSignal::new(None),
            account: RwSignal::new(None),
            generation: RwSignal::new(0),
            vault: RwSignal::new(None),
        }
    }

    pub fn initialize(self) {
        if self.worker_url.get_untracked().is_some() {
            return;
        }
        spawn_local(async move {
            let result = async {
                let response = gloo_net::http::Request::get("/crypto-worker.json")
                    .credentials(web_sys::RequestCredentials::SameOrigin)
                    .send()
                    .await
                    .map_err(|error| format!("Encryption worker manifest failed: {error}"))?;
                if !response.ok() {
                    return Err(format!(
                        "Encryption worker manifest returned HTTP {}.",
                        response.status()
                    ));
                }
                response
                    .json::<WorkerManifest>()
                    .await
                    .map_err(|error| format!("Encryption worker manifest is invalid: {error}"))
            }
            .await;
            match result {
                Ok(manifest) => {
                    self.worker_url.set(Some(manifest.worker_url));
                    self.status.set(EncryptionWorkerStatus::Ready);
                }
                Err(error) => self.status.set(EncryptionWorkerStatus::Unavailable(error)),
            }
        });
    }

    pub fn synchronize(self, account_id: Option<Uuid>, session_generation: u64) {
        let account_id = account_id.map(|account| account.to_string());
        let changed = SYNCHRONIZATION.with(|synchronization| {
            let current = synchronization.borrow();
            current.account_id != account_id || current.session_generation != session_generation
        });
        if !changed {
            return;
        }
        SYNCHRONIZATION.with(|synchronization| {
            *synchronization.borrow_mut() = WorkerSynchronization {
                account_id: account_id.clone(),
                session_generation,
            };
        });
        self.reset_worker();
        self.account.set(account_id.clone());
        if account_id.is_some() {
            self.refresh_vault_status();
        }
    }

    fn reset_worker(self) {
        self.generation
            .update(|generation| *generation = generation.wrapping_add(1));
        CLIENT.with(|client| {
            if let Some(client) = client.borrow_mut().take() {
                client.terminate();
            }
        });
        revoke_object_urls();
        self.vault.set(None);
        if self.worker_url.get_untracked().is_some() {
            self.status.set(EncryptionWorkerStatus::Ready);
        }
    }

    pub fn status(self) -> EncryptionWorkerStatus {
        self.status.get()
    }

    pub fn vault_unlocked(self) -> bool {
        let account = self.account.get();
        self.vault
            .get()
            .is_some_and(|vault| vault.unlocked && Some(vault.account_id) == account)
    }

    pub fn set_vault(self, vault: VaultInfo) {
        self.generation
            .update(|generation| *generation = generation.wrapping_add(1));
        self.vault.set(Some(vault));
    }

    pub fn refresh_vault_status(self) {
        let Some(account_id) = self.account.get_untracked() else {
            return;
        };
        let generation = self.generation.get_untracked();
        spawn_local(async move {
            let result = self
                .request_success(Command::VaultStatus {
                    account_id: account_id.clone(),
                })
                .await;
            if self.generation.get_untracked() != generation
                || self.account.get_untracked().as_deref() != Some(account_id.as_str())
            {
                return;
            }
            if self
                .vault
                .get_untracked()
                .is_some_and(|vault| vault.unlocked)
            {
                return;
            }
            if let Ok(success) = result
                && let salvage_crypto_worker::JobResult::Vault { vault } = success.result
            {
                self.vault.set(Some(vault));
            }
        });
    }

    pub async fn request_success(&self, command: Command) -> Result<JobSuccess, String> {
        let client = self.client()?;
        client
            .request(command)
            .await
            .map_err(|error| error.to_string())
    }

    pub async fn request_with_id(
        &self,
        job_id: String,
        command: Command,
    ) -> Result<JobSuccess, String> {
        let client = self.client()?;
        client
            .request_with_id(job_id, command)
            .await
            .map_err(|error| error.to_string())
    }

    pub fn cancel_job(self, job_id: String) {
        let Some(client) = CLIENT.with(|client| client.borrow().clone()) else {
            return;
        };
        spawn_local(async move {
            let _ = client
                .request(Command::Cancel {
                    account_id: None,
                    job_id: Some(job_id),
                })
                .await;
        });
    }

    fn client(&self) -> Result<WorkerClient, String> {
        if let Some(client) = CLIENT.with(|client| client.borrow().clone()) {
            return Ok(client);
        }
        let url = self
            .worker_url
            .get_untracked()
            .ok_or_else(|| "The encryption worker is still loading.".to_owned())?;
        let client = WorkerClient::new(&url).map_err(|error| error.to_string())?;
        CLIENT.with(|current| *current.borrow_mut() = Some(client.clone()));
        self.status.set(EncryptionWorkerStatus::Ready);
        Ok(client)
    }
}

pub fn save_decrypted_file(file: &File, original_name: &str) -> Result<(), String> {
    let url = Url::create_object_url_with_blob(file)
        .map_err(|_| "Couldn’t create the decrypted download URL.".to_owned())?;
    let document = web_sys::window()
        .and_then(|window| window.document())
        .ok_or_else(|| "Browser downloads are unavailable.".to_owned())?;
    let anchor = document
        .create_element("a")
        .map_err(|_| "Couldn’t create the download control.".to_owned())?
        .dyn_into::<HtmlElement>()
        .map_err(|_| "Couldn’t create the download control.".to_owned())?;
    anchor
        .set_attribute("href", &url)
        .map_err(|_| "Couldn’t prepare the decrypted download.".to_owned())?;
    anchor
        .set_attribute("download", original_name)
        .map_err(|_| "Couldn’t name the decrypted download.".to_owned())?;
    anchor.click();
    anchor.remove();
    OBJECT_URLS.with(|urls| urls.borrow_mut().insert(url.clone()));
    // Keep the URL alive for this account session. Browser download completion
    // is not observable, so an arbitrary timeout can cancel a valid download.
    Ok(())
}

fn revoke_object_urls() {
    OBJECT_URLS.with(|urls| {
        for url in urls.borrow_mut().drain() {
            let _ = Url::revoke_object_url(&url);
        }
    });
}
