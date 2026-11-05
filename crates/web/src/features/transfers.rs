use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use js_sys::Uint8Array;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::hooks::use_query_map;
use salvage_crypto_worker::{
    Command, ContinuationJournal, CredentialMode, JobResult, SecretString,
};
use salvage_protocol::{
    BotTokenInfo, CreateUploadRequest, Folder, SessionResponse, Transfer, TransferDirection,
    TransferStatus,
};
use uuid::Uuid;
use wasm_bindgen::JsCast;
use web_sys::{AbortController, AbortSignal, Event, File, HtmlInputElement};

use crate::api::{self, ApiError};
use crate::components::{Dialog, EmptyState, ErrorState, Icon, IconName, Protected, Spinner};
use crate::encryption::EncryptionContext;
use crate::features::ProtectedDownloadAction;
use crate::state::{SessionState, SessionStatus};
use crate::transfer_store::{self, ResumeMetadata};

const CHUNK_SIZE: u64 = 4 * 1024 * 1024;
const MAX_TRANSFER_BYTES: u64 = 2_000_000_000;

#[derive(Clone, Default)]
enum UploadProtection {
    #[default]
    Plain,
    Protected(Rc<CredentialMode>),
}

impl UploadProtection {
    fn is_protected(&self) -> bool {
        matches!(self, Self::Protected(_))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum UploadPhase {
    Creating,
    Verifying,
    Uploading,
    Publishing,
    Cancelling,
    Completed,
    Failed,
    Conflict,
    Cancelled,
}

impl UploadPhase {
    fn is_active(self) -> bool {
        matches!(
            self,
            Self::Creating | Self::Verifying | Self::Uploading | Self::Publishing
        )
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled)
    }
}

#[derive(Clone)]
struct QueuedUpload {
    local_id: Uuid,
    transfer_id: Option<Uuid>,
    name: String,
    size: u64,
    last_modified_ms: i64,
    folder_id: Option<String>,
    bot_id: Option<Uuid>,
    bot_auto: bool,
    transferred: u64,
    protected: bool,
    ciphertext_transferred: Option<u64>,
    ciphertext_size: Option<u64>,
    phase: UploadPhase,
    error: Option<String>,
}

#[derive(Clone)]
enum TransferListState {
    Loading,
    Ready,
    Error(String),
}

#[derive(Clone, Copy)]
pub struct TransferCenterState {
    queue: RwSignal<Vec<QueuedUpload>>,
    transfers: RwSignal<Vec<Transfer>>,
    list_state: RwSignal<TransferListState>,
    refresh: RwSignal<u64>,
    request_generation: RwSignal<u64>,
    refreshing: RwSignal<bool>,
    drive_revision: RwSignal<u64>,
    notice: RwSignal<Option<String>>,
    queue_cancelling: RwSignal<Option<Uuid>>,
    transfer_cancelling: RwSignal<Option<Uuid>>,
}

impl TransferCenterState {
    pub fn new() -> Self {
        Self {
            queue: RwSignal::new(Vec::new()),
            transfers: RwSignal::new(Vec::new()),
            list_state: RwSignal::new(TransferListState::Loading),
            refresh: RwSignal::new(0),
            request_generation: RwSignal::new(0),
            refreshing: RwSignal::new(false),
            drive_revision: RwSignal::new(0),
            notice: RwSignal::new(None),
            queue_cancelling: RwSignal::new(None),
            transfer_cancelling: RwSignal::new(None),
        }
    }

    pub fn reset(self) {
        runtime_abort_all();
        self.request_generation
            .update(|generation| *generation = generation.wrapping_add(1));
        self.queue.set(Vec::new());
        self.transfers.set(Vec::new());
        self.list_state.set(TransferListState::Loading);
        self.refreshing.set(false);
        self.notice.set(None);
        self.queue_cancelling.set(None);
        self.transfer_cancelling.set(None);
    }

    pub fn drive_revision(self) -> u64 {
        self.drive_revision.get()
    }

    pub fn record_transfer(self, transfer: Transfer) {
        self.transfers.update(|transfers| {
            if let Some(existing) = transfers
                .iter_mut()
                .find(|existing| existing.id == transfer.id)
            {
                if transfer.updated_at >= existing.updated_at {
                    *existing = transfer;
                }
            } else {
                transfers.insert(0, transfer);
            }
        });
        self.transfers.update(|transfers| {
            transfers.sort_by_key(|transfer| std::cmp::Reverse(transfer.updated_at));
        });
    }

    fn replace_transfers(self, incoming: Vec<Transfer>) {
        self.transfers.update(|current| {
            let mut merged = incoming;
            for old in current.iter() {
                if let Some(new) = merged.iter_mut().find(|new| new.id == old.id)
                    && old.updated_at > new.updated_at
                {
                    *new = old.clone();
                }
            }
            merged.sort_by_key(|transfer| std::cmp::Reverse(transfer.updated_at));
            *current = merged;
        });
    }

    fn request_refresh(self) {
        self.refresh
            .update(|version| *version = version.wrapping_add(1));
    }

    fn upload_completed(self, transfer: Transfer) {
        self.record_transfer(transfer);
        self.drive_revision
            .update(|revision| *revision = revision.wrapping_add(1));
    }
}

#[derive(Default)]
struct UploadRuntime {
    file: Option<File>,
    protection: UploadProtection,
    encryption: Option<EncryptionContext>,
    cancelled: bool,
    controller: Option<AbortController>,
}

thread_local! {
    static UPLOAD_RUNTIMES: RefCell<HashMap<Uuid, UploadRuntime>> = RefCell::new(HashMap::new());
}

fn runtime_start(local_id: Uuid, file: File) {
    UPLOAD_RUNTIMES.with(|runtimes| {
        let mut runtimes = runtimes.borrow_mut();
        let protection = runtimes
            .get(&local_id)
            .map(|runtime| runtime.protection.clone())
            .unwrap_or_default();
        let encryption = runtimes
            .get(&local_id)
            .and_then(|runtime| runtime.encryption);
        runtimes.insert(
            local_id,
            UploadRuntime {
                file: Some(file),
                protection,
                encryption,
                cancelled: false,
                controller: None,
            },
        );
    });
}

fn runtime_set_protection(local_id: Uuid, protection: UploadProtection) {
    UPLOAD_RUNTIMES.with(|runtimes| {
        if let Some(runtime) = runtimes.borrow_mut().get_mut(&local_id) {
            runtime.protection = protection;
        }
    });
}

fn runtime_protection(local_id: Uuid) -> UploadProtection {
    UPLOAD_RUNTIMES.with(|runtimes| {
        runtimes
            .borrow()
            .get(&local_id)
            .map(|runtime| runtime.protection.clone())
            .unwrap_or_default()
    })
}

fn runtime_set_encryption(local_id: Uuid, encryption: EncryptionContext) {
    UPLOAD_RUNTIMES.with(|runtimes| {
        if let Some(runtime) = runtimes.borrow_mut().get_mut(&local_id) {
            runtime.encryption = Some(encryption);
        }
    });
}

fn runtime_encryption(local_id: Uuid) -> Option<EncryptionContext> {
    UPLOAD_RUNTIMES.with(|runtimes| {
        runtimes
            .borrow()
            .get(&local_id)
            .and_then(|runtime| runtime.encryption)
    })
}

fn runtime_file(local_id: Uuid) -> Option<File> {
    UPLOAD_RUNTIMES.with(|runtimes| {
        runtimes
            .borrow()
            .get(&local_id)
            .and_then(|runtime| runtime.file.clone())
    })
}

fn runtime_signal(local_id: Uuid) -> Option<AbortSignal> {
    UPLOAD_RUNTIMES.with(|runtimes| {
        let mut runtimes = runtimes.borrow_mut();
        let runtime = runtimes.get_mut(&local_id)?;
        let controller = AbortController::new().ok()?;
        let signal = controller.signal();
        runtime.controller = Some(controller);
        Some(signal)
    })
}

fn runtime_clear_controller(local_id: Uuid) {
    UPLOAD_RUNTIMES.with(|runtimes| {
        if let Some(runtime) = runtimes.borrow_mut().get_mut(&local_id) {
            runtime.controller = None;
        }
    });
}

fn runtime_cancel(local_id: Uuid) {
    UPLOAD_RUNTIMES.with(|runtimes| {
        if let Some(runtime) = runtimes.borrow_mut().get_mut(&local_id) {
            runtime.cancelled = true;
            if let Some(controller) = runtime.controller.take() {
                controller.abort();
            }
        }
    });
}

fn runtime_is_cancelled(local_id: Uuid) -> bool {
    UPLOAD_RUNTIMES.with(|runtimes| {
        runtimes
            .borrow()
            .get(&local_id)
            .map(|runtime| runtime.cancelled)
            .unwrap_or(true)
    })
}

fn runtime_finish(local_id: Uuid) {
    UPLOAD_RUNTIMES.with(|runtimes| {
        runtimes.borrow_mut().remove(&local_id);
    });
}

fn runtime_abort_all() {
    UPLOAD_RUNTIMES.with(|runtimes| {
        for (_, runtime) in runtimes.borrow_mut().drain() {
            if let Some(controller) = runtime.controller {
                controller.abort();
            }
        }
    });
}

#[component]
pub fn TransfersPage() -> impl IntoView {
    view! { <Protected><TransfersWorkspace/></Protected> }
}

#[component]
fn TransfersWorkspace() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let center = expect_context::<TransferCenterState>();
    let encryption = expect_context::<EncryptionContext>();
    let query = use_query_map();
    let folder_id = move || query.get().get("folder_id");
    let protection_mode = RwSignal::new("plain".to_owned());
    let pending_protected_files = RwSignal::new(Vec::<File>::new());
    let protected_prompt_file = RwSignal::new(Option::<File>::None);
    let protected_prompt_vault = RwSignal::new(false);
    let protected_passphrase = RwSignal::new(String::new());
    let protected_prompt_error = RwSignal::new(Option::<String>::None);
    let protected_prompt_busy = RwSignal::new(false);
    let selected_bot = RwSignal::new(None::<Uuid>);
    let bots = RwSignal::new(Vec::<BotTokenInfo>::new());
    let bot_auto = RwSignal::new(false);
    let destination_mode = RwSignal::new("root".to_owned());
    let active_folder = RwSignal::new(None::<Folder>);

    Effect::new(move |_| {
        let SessionStatus::Authenticated(authenticated) = session.status.get() else {
            return;
        };
        let generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        spawn_local(async move {
            if let Ok(result) = api::list_bots().await
                && session.is_current(generation, account_id)
            {
                bots.set(result);
            }
            if let Ok(folders) = api::list_folders(None).await
                && session.is_current(generation, account_id)
            {
                active_folder.set(folders.into_iter().find(|folder| folder.active));
            }
        });
    });

    Effect::new(move |_| {
        let _ = center.refresh.get();
        let SessionStatus::Authenticated(authenticated) = session.status.get() else {
            return;
        };
        let account_id = authenticated.account.id;
        let auth_generation = session.generation.get_untracked();
        center
            .request_generation
            .update(|generation| *generation = generation.wrapping_add(1));
        let own_request = center.request_generation.get_untracked();
        center.refreshing.set(true);
        if center.transfers.get_untracked().is_empty() {
            center.list_state.set(TransferListState::Loading);
        }

        spawn_local(async move {
            let result = api::list_transfers().await;
            if center.request_generation.get_untracked() != own_request
                || !session.is_current(auth_generation, account_id)
            {
                return;
            }
            center.refreshing.set(false);
            match result {
                Ok(transfers) => {
                    center.replace_transfers(transfers);
                    center.list_state.set(TransferListState::Ready);
                }
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                }
                Err(error) => center
                    .list_state
                    .set(TransferListState::Error(error.message)),
            }
        });
    });

    let select_files = move |event: Event| {
        let Some(input) = event
            .target()
            .and_then(|target| target.dyn_into::<HtmlInputElement>().ok())
        else {
            return;
        };
        let destination = folder_id().or_else(|| {
            if destination_mode.get_untracked() == "active" {
                active_folder.get_untracked().map(|folder| folder.id)
            } else {
                None
            }
        });
        if destination.is_none() {
            selected_bot.set(None);
            bot_auto.set(false);
        }
        let mode = protection_mode.get_untracked();
        if let Some(files) = input.files() {
            for index in 0..files.length() {
                if let Some(file) = files.item(index) {
                    if mode == "plain" {
                        start_upload(
                            center,
                            session,
                            file,
                            destination.clone(),
                            false,
                            UploadProtection::Plain,
                            selected_bot.get_untracked(),
                            bot_auto.get_untracked(),
                        );
                    } else {
                        protected_prompt_vault.set(mode == "vault");
                        pending_protected_files.update(|pending| pending.push(file));
                    }
                }
            }
        }
        if mode != "plain" && protected_prompt_file.get_untracked().is_none() {
            advance_protected_prompt(pending_protected_files, protected_prompt_file);
        }
        input.set_value("");
    };

    let use_protected_credential = Callback::new(move |_: ()| {
        let Some(file) = protected_prompt_file.get_untracked() else {
            return;
        };
        let use_vault = protected_prompt_vault.get_untracked();
        let passphrase = protected_passphrase.get_untracked();
        let vault_unlocked = encryption.vault_unlocked();
        if (!use_vault || !vault_unlocked) && passphrase.is_empty() {
            protected_prompt_error.set(Some(
                "Enter a passphrase to continue with protected upload.".to_owned(),
            ));
            return;
        }
        protected_passphrase.set(String::new());
        protected_prompt_error.set(None);
        let destination = folder_id();
        if use_vault && !vault_unlocked {
            let Some(authenticated) = current_session(session) else {
                return;
            };
            let generation = session.generation.get_untracked();
            let account_id = authenticated.account.id;
            protected_prompt_busy.set(true);
            spawn_local(async move {
                let result = encryption
                    .request_success(Command::VaultUnlock {
                        account_id: account_id.to_string(),
                        passphrase: passphrase.into(),
                    })
                    .await;
                if !session.is_current(generation, account_id) {
                    return;
                }
                protected_prompt_busy.set(false);
                match result {
                    Ok(success) => {
                        if let JobResult::Vault { vault } = success.result {
                            encryption.set_vault(vault);
                        }
                        start_upload(
                            center,
                            session,
                            file,
                            destination,
                            false,
                            UploadProtection::Protected(Rc::new(CredentialMode::UnlockedVault)),
                            selected_bot.get_untracked(),
                            bot_auto.get_untracked(),
                        );
                        advance_protected_prompt(pending_protected_files, protected_prompt_file);
                    }
                    Err(message) => protected_prompt_error.set(Some(message)),
                }
            });
        } else {
            let credential = if use_vault {
                CredentialMode::UnlockedVault
            } else {
                CredentialMode::Passphrase {
                    passphrase: SecretString::from(passphrase),
                }
            };
            start_upload(
                center,
                session,
                file,
                destination,
                false,
                UploadProtection::Protected(Rc::new(credential)),
                selected_bot.get_untracked(),
                bot_auto.get_untracked(),
            );
            advance_protected_prompt(pending_protected_files, protected_prompt_file);
        }
    });

    let close_protected_prompt: Callback<()> = Callback::new(move |_: ()| {
        protected_prompt_file.set(None);
        pending_protected_files.set(Vec::new());
        protected_passphrase.set(String::new());
        protected_prompt_error.set(None);
        protected_prompt_busy.set(false);
    });

    let cancel_queued = Callback::new(move |local_id: Uuid| {
        let Some(item) = center
            .queue
            .get_untracked()
            .into_iter()
            .find(|item| item.local_id == local_id)
        else {
            return;
        };
        if item.phase.is_terminal() || item.phase == UploadPhase::Cancelling {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let account_id = authenticated.account.id;
        let auth_generation = session.generation.get_untracked();
        center.queue_cancelling.set(Some(local_id));
        runtime_cancel(local_id);
        encryption.cancel_job(local_id.to_string());
        update_queued(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            |item| {
                item.phase = UploadPhase::Cancelling;
                item.error = None;
            },
        );

        if item.phase.is_active() {
            // The upload task confirms cancellation after any in-flight create/chunk settles.
            return;
        }

        spawn_local(async move {
            cancel_inactive_upload(
                center,
                session,
                authenticated,
                auth_generation,
                account_id,
                local_id,
                item.transfer_id,
            )
            .await;
        });
    });

    let retry_upload = Callback::new(move |local_id: Uuid| {
        if let Some(file) = runtime_file(local_id) {
            center.notice.set(None);
            runtime_start(local_id, file.clone());
            if let Some(item) = queued_item(center, local_id) {
                start_existing_upload(center, session, local_id, file, item.folder_id, false);
            }
        } else {
            update_queued_unguarded(center, local_id, |item| {
                item.error = Some("Reselect the original file to retry this upload.".to_owned());
            });
        }
    });

    let restart_upload = Callback::new(move |local_id: Uuid| {
        let Some(item) = queued_item(center, local_id) else {
            return;
        };
        let Some(file) = runtime_file(local_id) else {
            update_queued_unguarded(center, local_id, |item| {
                item.error = Some("Reselect the original file to start a new upload.".to_owned());
            });
            return;
        };
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let account_id = authenticated.account.id;
        let auth_generation = session.generation.get_untracked();
        let transfer_id = item.transfer_id.or_else(|| {
            center
                .transfers
                .get_untracked()
                .into_iter()
                .find(|transfer| {
                    transfer.direction == TransferDirection::Upload
                        && transfer.name == item.name
                        && transfer.size == item.size
                        && transfer.source_modified_ms == Some(item.last_modified_ms)
                        && transfer.folder_id == item.folder_id
                        && matches!(
                            transfer.status,
                            TransferStatus::Staging | TransferStatus::Failed
                        )
                })
                .map(|transfer| transfer.id)
        });
        let Some(transfer_id) = transfer_id else {
            update_queued_unguarded(center, local_id, |item| {
                item.error = Some(
                    "Refresh the transfer list, then restart so the old staged upload can be discarded."
                        .to_owned(),
                );
            });
            return;
        };

        update_queued_unguarded(center, local_id, |item| {
            item.phase = UploadPhase::Creating;
            item.error = None;
        });
        spawn_local(async move {
            let result = api::cancel_transfer(transfer_id, &authenticated.csrf_token).await;
            if !session.is_current(auth_generation, account_id) {
                return;
            }
            match result {
                Ok(transfer) => center.record_transfer(transfer),
                Err(error) if error.status == Some(404) => {}
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                    return;
                }
                Err(error) => {
                    update_queued_unguarded(center, local_id, |item| {
                        item.phase = UploadPhase::Conflict;
                        item.error = Some(format!(
                            "The old staged upload couldn’t be discarded. {}",
                            error.message
                        ));
                    });
                    return;
                }
            }
            transfer_store::remove(transfer_id);
            runtime_start(local_id, file.clone());
            start_existing_upload(center, session, local_id, file, item.folder_id, true);
        });
    });

    let cancel_server = Callback::new(move |transfer_id: Uuid| {
        let Some(transfer) = center
            .transfers
            .get_untracked()
            .into_iter()
            .find(|transfer| transfer.id == transfer_id)
        else {
            return;
        };
        if !can_cancel(transfer.status.clone()) {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let account_id = authenticated.account.id;
        let auth_generation = session.generation.get_untracked();
        center.transfer_cancelling.set(Some(transfer_id));
        spawn_local(async move {
            let result = api::cancel_transfer(transfer_id, &authenticated.csrf_token).await;
            if !session.is_current(auth_generation, account_id) {
                return;
            }
            center.transfer_cancelling.set(None);
            match result {
                Ok(transfer) => {
                    if transfer.direction == TransferDirection::Upload {
                        transfer_store::remove(transfer.id);
                    }
                    center.record_transfer(transfer);
                }
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                }
                Err(error) => center.notice.set(Some(format!(
                    "Couldn’t cancel “{}”. {}",
                    transfer.name, error.message
                ))),
            }
        });
    });

    let refresh = Callback::new(move |_| center.request_refresh());
    let visible_transfers = move || {
        let queued_ids: Vec<Uuid> = center
            .queue
            .get()
            .into_iter()
            .filter_map(|item| item.transfer_id)
            .collect();
        center
            .transfers
            .get()
            .into_iter()
            .filter(|transfer| !queued_ids.contains(&transfer.id))
            .collect::<Vec<_>>()
    };
    let active_count = move || {
        let queued = center
            .queue
            .get()
            .into_iter()
            .filter(|item| item.phase.is_active())
            .count();
        let server = visible_transfers()
            .into_iter()
            .filter(|transfer| {
                matches!(
                    transfer.status,
                    TransferStatus::Staging | TransferStatus::Publishing
                )
            })
            .count();
        queued + server
    };

    view! {
        <div class="transfers-page transfers-live-page">
            <section class="transfers-heading">
                <div>
                    <span class="eyebrow">"Transfer center"</span>
                    <h2>"Move files with confidence."</h2>
                    <p>"Upload in verified 4 MiB chunks, resume with the original file, and prepare browser downloads."</p>
                </div>
                <button class="button button-secondary" type="button" disabled=move || center.refreshing.get() on:click=move |_| refresh.run(())>
                    {move || if center.refreshing.get() { view! { <Spinner/> }.into_any() } else { view! { <Icon icon=IconName::Refresh size=18/> }.into_any() }}
                    <span>"Refresh"</span>
                </button>
            </section>

            <section class="upload-panel" aria-labelledby="upload-panel-heading">
                <span class="upload-panel-icon"><Icon icon=IconName::Upload size=25/></span>
                <div class="upload-panel-copy">
                    <h3 id="upload-panel-heading">"Upload files"</h3>
                    <p>{move || if folder_id().is_some() { "Files will be added to the current drive folder." } else { "Files will be added to your drive’s root folder." }}</p>
                    <span>"Select multiple files. Each file uploads sequentially; independent files may upload together."</span>
                </div>
                <Show when=move || folder_id().is_none()>
                    <div class="upload-protection">
                        <label for="upload-destination">"Destination"</label>
                        <select id="upload-destination" on:change=move |event| destination_mode.set(event_target_value(&event))>
                            <option value="root" selected=move || destination_mode.get() == "root">"Saved Messages"</option>
                            <option value="active" selected=move || destination_mode.get() == "active" disabled=move || active_folder.get().is_none()>"Active channel"</option>
                        </select>
                        <span>{move || active_folder.get().map(|folder| format!("Active: {}", folder.name)).unwrap_or_else(|| "Select a channel in Drive first.".to_string())}</span>
                    </div>
                </Show>
                <div class="upload-protection">
                    <label for="upload-protection">"Protection"</label>
                    <select id="upload-protection" on:change=move |event| protection_mode.set(event_target_value(&event))>
                        <option value="plain" selected=move || protection_mode.get() == "plain">"Plain (default)"</option>
                        <option value="passphrase" selected=move || protection_mode.get() == "passphrase">"Encrypt with passphrase"</option>
                        <option value="vault" selected=move || protection_mode.get() == "vault">"Encrypt with unlocked vault"</option>
                    </select>
                </div>
                <Show when=move || folder_id().is_some()>
                    <div class="upload-protection">
                        <label for="upload-bot">"Upload identity"</label>
                        <select id="upload-bot" on:change=move |event| {
                            let value = event_target_value(&event);
                            bot_auto.set(value == "auto");
                            selected_bot.set(Uuid::parse_str(&value).ok());
                        }>
                            <option value="" selected=move || selected_bot.get().is_none() && !bot_auto.get()>"Personal account"</option>
                            <option value="auto" selected=move || bot_auto.get()>"Auto (least-loaded bot)"</option>
                            <For each=move || bots.get() key=|bot| bot.id children=move |bot| {
                                let id = bot.id.to_string();
                                let selected = selected_bot.get() == Some(bot.id);
                                view! { <option value=id selected=selected>{bot.label.clone()}</option> }
                            }/>
                        </select>
                        <span>"Bots are accepted only with channel admin rights."</span>
                    </div>
                </Show>
                <label class="upload-picker button button-primary">
                    <Icon icon=IconName::Plus size=18/>
                    <span>"Choose files"</span>
                    <input type="file" multiple aria-label="Upload files" on:change=select_files/>
                </label>
            </section>

            <div class="resume-explainer">
                <Icon icon=IconName::Shield size=17/>
                <p>"To resume after a reload, select the original file again. Salvage Cloud verifies its staged prefix with SHA-256. Only transfer metadata—not file contents or credentials—is saved in this browser."</p>
            </div>

            {move || center.notice.get().map(|notice| view! {
                <div class="inline-notice notice-warning" role="alert"><Icon icon=IconName::Alert size=18/><span>{notice}</span></div>
            })}

            <div class="transfer-list-summary">
                <h3>"Activity"</h3>
                <span>{move || format!("{} active", active_count())}</span>
            </div>

            {move || match center.list_state.get() {
                TransferListState::Error(message) if center.queue.get().is_empty() && visible_transfers().is_empty() => view! {
                    <ErrorState title="Transfers didn’t load" message=message on_retry=refresh/>
                }.into_any(),
                _ => view! {
                    <Show when=move || center.queue.get().is_empty() && visible_transfers().is_empty() && !matches!(center.list_state.get(), TransferListState::Loading)>
                        <EmptyState title="No transfers yet" message="Choose files to start your first upload, or download a file from your drive."/>
                    </Show>
                    <Show when=move || matches!(center.list_state.get(), TransferListState::Loading) && center.queue.get().is_empty()>
                        <div class="transfer-loading" role="status"><Spinner size=22/><span>"Loading transfer activity…"</span></div>
                    </Show>
                    <div class="transfer-list" role="list" aria-label="Transfers">
                        <For
                            each=move || center.queue.get()
                            key=|item| (item.local_id, item.transferred, item.phase as u8, item.transfer_id, item.error.clone())
                            children=move |item| view! {
                                <QueuedTransferRow item=item on_cancel=cancel_queued on_retry=retry_upload on_restart=restart_upload cancelling=center.queue_cancelling/>
                            }
                        />
                        <For
                            each=visible_transfers
                            key=|transfer| (transfer.id, transfer.transferred, transfer.updated_at.timestamp_millis(), transfer.error.clone())
                            children=move |transfer| view! {
                                <ServerTransferRow transfer=transfer on_cancel=cancel_server cancelling=center.transfer_cancelling request_generation=center.request_generation/>
                            }
                        />
                    </div>
                }.into_any(),
            }}

            <Show when=move || protected_prompt_file.get().is_some()>
                <Dialog title="Protect this upload" description="The original name and MIME type are sent only to the encryption worker. The backend receives a generic .tdenc2 envelope.".to_owned() on_close=close_protected_prompt>
                    <div class="protected-upload-prompt">
                        <p class="protected-file-name">{move || protected_prompt_file.get().map(|file| file.name()).unwrap_or_default()}</p>
                        <label for="protected-upload-passphrase">"Passphrase"</label>
                        <input id="protected-upload-passphrase" type="password" autocomplete="off" prop:value=move || protected_passphrase.get() on:input=move |event| protected_passphrase.set(event_target_value(&event))/>
                        {move || protected_prompt_error.get().map(|message| view! {
                            <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div>
                        })}
                        <button class="button button-primary button-full" type="button" disabled=move || protected_prompt_busy.get() on:click=move |_| use_protected_credential.run(())>
                            {move || if protected_prompt_busy.get() { view! { <Spinner/> }.into_any() } else { view! { <Icon icon=IconName::Lock size=17/> }.into_any() }}
                            {move || if protected_prompt_vault.get() {
                                if encryption.vault_unlocked() { "Use unlocked vault" } else { "Unlock vault" }
                            } else {
                                "Use passphrase"
                            }}
                        </button>
                        <p class="field-help">"Plain upload remains the default. Protected credentials are used only for this file and are never persisted."</p>
                    </div>
                </Dialog>
            </Show>
        </div>
    }
}

#[component]
fn QueuedTransferRow(
    item: QueuedUpload,
    on_cancel: Callback<Uuid>,
    on_retry: Callback<Uuid>,
    on_restart: Callback<Uuid>,
    cancelling: RwSignal<Option<Uuid>>,
) -> impl IntoView {
    let local_id = item.local_id;
    let name = item.name.clone();
    let progress = progress_percent(
        item.transferred,
        item.size,
        item.phase == UploadPhase::Completed,
    );
    let status = match item.phase {
        UploadPhase::Creating => "Creating upload",
        UploadPhase::Verifying => "Verifying staged content",
        UploadPhase::Uploading => "Uploading",
        UploadPhase::Publishing => "Publishing to your drive",
        UploadPhase::Cancelling => "Cancelling",
        UploadPhase::Completed => "Completed",
        UploadPhase::Failed => "Needs attention",
        UploadPhase::Conflict => "Restart required",
        UploadPhase::Cancelled => "Cancelled",
    };
    let status_class = match item.phase {
        UploadPhase::Completed => "transfer-status is-completed",
        UploadPhase::Failed | UploadPhase::Conflict => "transfer-status is-failed",
        UploadPhase::Cancelled => "transfer-status is-cancelled",
        _ => "transfer-status is-active",
    };
    let cancel_label = format!("Cancel transfer {name}");
    let error = item.error.clone();
    let protected = item.protected;
    let ciphertext_progress = item.ciphertext_transferred.zip(item.ciphertext_size);

    view! {
        <article class="transfer-row" role="listitem">
            <span class="transfer-direction-icon"><Icon icon=IconName::Upload size=21/></span>
            <div class="transfer-row-main">
                <div class="transfer-row-title"><strong>{name.clone()}</strong><span class=status_class>{status}</span>{protected.then(|| view! { <span class="transfer-status is-completed">"Protected"</span> })}</div>
                <div class="transfer-progress-line">
                    <progress max="100" value=progress aria-label=format!("Upload progress for {name}")></progress>
                    <span>{format!("{progress}%")}</span>
                </div>
                <div class="transfer-meta"><span>{format!("{} of {}", format_size(item.transferred), format_size(item.size))}</span><span>"Upload"</span></div>
                {ciphertext_progress.map(|(transferred, size)| view! {
                    <div class="transfer-meta ciphertext-meta"><span>{format!("Ciphertext: {} of {}", format_size(transferred), format_size(size))}</span></div>
                })}
                {error.map(|message| view! { <p class="transfer-error" role="alert">{message}</p> })}
                <Show when=move || item.phase == UploadPhase::Conflict>
                    <p class="transfer-action-hint">"Restart discards the old staged content before uploading this file from the beginning."</p>
                </Show>
            </div>
            <div class="transfer-row-actions">
                {match item.phase {
                    UploadPhase::Conflict => Some(view! {
                        <button class="button button-secondary button-small" type="button" on:click=move |_| on_restart.run(local_id)><Icon icon=IconName::Refresh size=16/>"Restart upload"</button>
                    }.into_any()),
                    UploadPhase::Failed => Some(view! {
                        <button class="button button-secondary button-small" type="button" on:click=move |_| on_retry.run(local_id)><Icon icon=IconName::Refresh size=16/>"Retry"</button>
                    }.into_any()),
                    _ => None,
                }}
                <Show when=move || !item.phase.is_terminal() && item.phase != UploadPhase::Cancelling>
                    <button class="icon-button danger-hover" type="button" aria-label=cancel_label.clone() title="Cancel transfer" disabled=move || cancelling.get() == Some(local_id) on:click=move |_| on_cancel.run(local_id)>
                        <Icon icon=IconName::Close size=19/>
                    </button>
                </Show>
            </div>
        </article>
    }
}

#[component]
fn ServerTransferRow(
    transfer: Transfer,
    on_cancel: Callback<Uuid>,
    cancelling: RwSignal<Option<Uuid>>,
    request_generation: RwSignal<u64>,
) -> impl IntoView {
    let transfer_id = transfer.id;
    let is_upload = transfer.direction == TransferDirection::Upload;
    let name = transfer.name.clone();
    let status = status_label(&transfer);
    let status_class = match transfer.status {
        TransferStatus::Completed | TransferStatus::Ready => "transfer-status is-completed",
        TransferStatus::Failed => "transfer-status is-failed",
        TransferStatus::Cancelled => "transfer-status is-cancelled",
        _ => "transfer-status is-active",
    };
    let progress = progress_percent(
        transfer.transferred,
        transfer.size,
        matches!(
            transfer.status,
            TransferStatus::Completed | TransferStatus::Ready
        ),
    );
    let download_url = format!("/api/v1/transfers/{transfer_id}/content");
    let download_label = format!("Download {name}");
    let cancel_label = format!("Cancel transfer {name}");
    let show_resume_hint = is_upload
        && matches!(
            transfer.status,
            TransferStatus::Staging | TransferStatus::Failed
        );
    let ready = transfer.status == TransferStatus::Ready;
    let cancellable = can_cancel(transfer.status.clone());
    let protected = transfer.protected;
    let source_file_id = transfer.source_file_id.clone();
    let protected_size = transfer.size;

    view! {
        <article class="transfer-row" role="listitem">
            <span class="transfer-direction-icon">{if is_upload { view! { <Icon icon=IconName::Upload size=21/> }.into_any() } else { view! { <Icon icon=IconName::Download size=21/> }.into_any() }}</span>
            <div class="transfer-row-main">
                <div class="transfer-row-title"><strong>{name.clone()}</strong><span class=status_class>{status}</span>{protected.then(|| view! { <span class="transfer-status is-completed">"Protected"</span> })}</div>
                <div class="transfer-progress-line">
                    <progress max="100" value=progress aria-label=format!("Transfer progress for {name}")></progress>
                    <span>{format!("{progress}%")}</span>
                </div>
                <div class="transfer-meta"><span>{format!("{} of {}", format_size(transfer.transferred), format_size(transfer.size))}</span><span>{if is_upload { "Upload" } else { "Download" }}</span></div>
                {transfer.error.clone().map(|message| view! { <p class="transfer-error" role="alert">{message}</p> })}
                <Show when=move || show_resume_hint>
                    <p class="transfer-action-hint">"Reselect the original file with Upload files to verify and resume this upload."</p>
                </Show>
            </div>
            <div class="transfer-row-actions">
                <Show when=move || ready>
                    {if protected {
                        view! { <ProtectedDownloadAction file_id=source_file_id.clone().unwrap_or_default() transfer_id=transfer_id expected_ciphertext_len=protected_size name=name.clone() request_generation=request_generation/> }.into_any()
                    } else {
                        view! { <a class="button button-secondary button-small" href=download_url.clone() aria-label=download_label.clone()><Icon icon=IconName::Download size=16/>"Download"</a> }.into_any()
                    }}
                </Show>
                <Show when=move || cancellable>
                    <button class="icon-button danger-hover" type="button" aria-label=cancel_label.clone() title="Cancel transfer" disabled=move || cancelling.get() == Some(transfer_id) on:click=move |_| on_cancel.run(transfer_id)>
                        <Icon icon=IconName::Close size=19/>
                    </button>
                </Show>
            </div>
        </article>
    }
}

fn advance_protected_prompt(pending: RwSignal<Vec<File>>, current: RwSignal<Option<File>>) {
    let next = pending.get_untracked().first().cloned();
    pending.update(|pending| {
        if !pending.is_empty() {
            pending.remove(0);
        }
    });
    current.set(next);
}

#[allow(clippy::too_many_arguments)]
fn start_upload(
    center: TransferCenterState,
    session: SessionState,
    file: File,
    folder_id: Option<String>,
    force_restart: bool,
    protection: UploadProtection,
    bot_id: Option<Uuid>,
    bot_auto: bool,
) {
    let local_id = Uuid::new_v4();
    let name = file.name().trim().to_owned();
    let size = file.size() as u64;
    let last_modified_ms = file.last_modified() as i64;
    center.notice.set(None);

    if name.is_empty() || size > MAX_TRANSFER_BYTES {
        center.queue.update(|queue| {
            queue.insert(
                0,
                QueuedUpload {
                    local_id,
                    transfer_id: None,
                    name: if name.is_empty() {
                        "Unnamed file".to_owned()
                    } else {
                        name
                    },
                    size,
                    last_modified_ms,
                    folder_id,
                    bot_id,
                    bot_auto,
                    transferred: 0,
                    protected: protection.is_protected(),
                    ciphertext_transferred: None,
                    ciphertext_size: None,
                    phase: UploadPhase::Failed,
                    error: Some(if size > MAX_TRANSFER_BYTES {
                        "This file exceeds the 2,000,000,000-byte transfer limit.".to_owned()
                    } else {
                        "The file must have a valid name.".to_owned()
                    }),
                },
            );
        });
        return;
    }

    let duplicate = center.queue.get_untracked().into_iter().any(|item| {
        item.name == name
            && item.size == size
            && item.last_modified_ms == last_modified_ms
            && item.folder_id == folder_id
            && item.phase.is_active()
    });
    if duplicate {
        center.notice.set(Some(format!(
            "“{name}” is already being uploaded. Wait for it to finish or cancel it first."
        )));
        return;
    }

    center.queue.update(|queue| {
        queue.retain(|item| {
            let replace = item.name == name
                && item.size == size
                && item.last_modified_ms == last_modified_ms
                && item.folder_id == folder_id;
            if replace {
                runtime_finish(item.local_id);
            }
            !replace
        });
        queue.insert(
            0,
            QueuedUpload {
                local_id,
                transfer_id: None,
                name: name.clone(),
                size,
                last_modified_ms,
                folder_id: folder_id.clone(),
                bot_id,
                bot_auto,
                transferred: 0,
                protected: protection.is_protected(),
                ciphertext_transferred: None,
                ciphertext_size: None,
                phase: UploadPhase::Creating,
                error: None,
            },
        );
    });
    runtime_start(local_id, file.clone());
    runtime_set_protection(local_id, protection);
    runtime_set_encryption(local_id, expect_context::<EncryptionContext>());
    start_existing_upload(center, session, local_id, file, folder_id, force_restart);
}

fn start_existing_upload(
    center: TransferCenterState,
    session: SessionState,
    local_id: Uuid,
    file: File,
    folder_id: Option<String>,
    force_restart: bool,
) {
    let protection = runtime_protection(local_id);
    let bot_id = queued_item(center, local_id).and_then(|item| item.bot_id);
    let bot_auto = queued_item(center, local_id).is_some_and(|item| item.bot_auto);
    spawn_local(async move {
        run_upload(
            center,
            session,
            local_id,
            file,
            folder_id,
            force_restart,
            protection,
            bot_id,
            bot_auto,
        )
        .await;
    });
}

#[allow(clippy::too_many_arguments)]
async fn run_upload(
    center: TransferCenterState,
    session: SessionState,
    local_id: Uuid,
    file: File,
    folder_id: Option<String>,
    force_restart: bool,
    protection: UploadProtection,
    bot_id: Option<Uuid>,
    bot_auto: bool,
) {
    if protection.is_protected() {
        run_protected_upload(
            center,
            session,
            local_id,
            file,
            folder_id,
            force_restart,
            protection,
            bot_id,
            bot_auto,
        )
        .await;
    } else {
        run_plain_upload(
            center,
            session,
            local_id,
            file,
            folder_id,
            force_restart,
            bot_id,
            bot_auto,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_plain_upload(
    center: TransferCenterState,
    session: SessionState,
    local_id: Uuid,
    file: File,
    folder_id: Option<String>,
    force_restart: bool,
    bot_id: Option<Uuid>,
    bot_auto: bool,
) {
    let Some(authenticated) = current_session(session) else {
        runtime_finish(local_id);
        return;
    };
    let auth_generation = session.generation.get_untracked();
    let account_id = authenticated.account.id;
    let name = file.name().trim().to_owned();
    let size = file.size() as u64;
    let last_modified_ms = file.last_modified() as i64;

    let mut resume = None;
    let mut prefix_sha256 = None;
    if !force_restart {
        resume = transfer_store::find(
            &name,
            size,
            last_modified_ms,
            folder_id.as_deref(),
            bot_id,
            bot_auto,
        );
        if let Some(record) = &resume {
            update_queued(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                |item| {
                    item.transfer_id = Some(record.transfer_id);
                    item.transferred = record.next_offset;
                    item.phase = UploadPhase::Verifying;
                },
            );
            match transfer_store::sha256_prefix(&file, record.next_offset).await {
                Ok(hash) => prefix_sha256 = Some(hash),
                Err(error) => {
                    fail_upload(
                        center,
                        session,
                        auth_generation,
                        account_id,
                        local_id,
                        error,
                        false,
                    );
                    return;
                }
            }
        }
    }

    if !session.is_current(auth_generation, account_id) {
        runtime_finish(local_id);
        return;
    }
    if runtime_is_cancelled(local_id) {
        finish_cancelled_upload(
            center,
            session,
            &authenticated,
            auth_generation,
            account_id,
            local_id,
            resume.as_ref().map(|record| record.transfer_id),
        )
        .await;
        return;
    }

    let mime_type = match file.type_().trim() {
        "" => "application/octet-stream".to_owned(),
        value => value.to_owned(),
    };
    let request = CreateUploadRequest {
        name: name.clone(),
        folder_id: folder_id.clone(),
        size,
        mime_type,
        source_modified_ms: Some(last_modified_ms),
        prefix_sha256,
        protected: false,
        bot_id,
        bot_auto,
    };
    let signal = runtime_signal(local_id);
    let created = api::create_upload(&request, &authenticated.csrf_token, signal.as_ref()).await;
    runtime_clear_controller(local_id);
    if !session.is_current(auth_generation, account_id) {
        runtime_finish(local_id);
        return;
    }
    let upload = match created {
        Ok(upload) => upload,
        Err(error) => {
            if runtime_is_cancelled(local_id) {
                finish_cancelled_upload(
                    center,
                    session,
                    &authenticated,
                    auth_generation,
                    account_id,
                    local_id,
                    resume.as_ref().map(|record| record.transfer_id),
                )
                .await;
            } else {
                handle_upload_error(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    error,
                );
            }
            return;
        }
    };
    let transfer_id = upload.transfer.id;
    if upload.next_offset > size || upload.transfer.size != size {
        fail_upload(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            "The server returned an invalid upload offset. Restart with new staged content."
                .to_owned(),
            true,
        );
        return;
    }
    if runtime_is_cancelled(local_id) {
        finish_cancelled_upload(
            center,
            session,
            &authenticated,
            auth_generation,
            account_id,
            local_id,
            Some(transfer_id),
        )
        .await;
        return;
    }

    save_resume(
        &upload.transfer,
        last_modified_ms,
        upload.next_offset,
        bot_id,
        bot_auto,
    );
    center.record_transfer(upload.transfer.clone());
    update_queued(
        center,
        session,
        auth_generation,
        account_id,
        local_id,
        |item| {
            item.transfer_id = Some(transfer_id);
            item.transferred = upload.next_offset;
            item.phase = UploadPhase::Uploading;
            item.error = None;
        },
    );

    let mut offset = upload.next_offset;
    while offset < size {
        if runtime_is_cancelled(local_id) {
            finish_cancelled_upload(
                center,
                session,
                &authenticated,
                auth_generation,
                account_id,
                local_id,
                Some(transfer_id),
            )
            .await;
            return;
        }
        let end = offset.saturating_add(CHUNK_SIZE).min(size);
        let bytes = match transfer_store::read_chunk(&file, offset, end).await {
            Ok(bytes) => bytes,
            Err(error) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    error,
                    false,
                );
                return;
            }
        };
        if runtime_is_cancelled(local_id) {
            finish_cancelled_upload(
                center,
                session,
                &authenticated,
                auth_generation,
                account_id,
                local_id,
                Some(transfer_id),
            )
            .await;
            return;
        }
        let signal = runtime_signal(local_id);
        let appended = append_chunk(
            transfer_id,
            offset,
            bytes,
            &authenticated.csrf_token,
            signal.as_ref(),
        )
        .await;
        runtime_clear_controller(local_id);
        if !session.is_current(auth_generation, account_id) {
            runtime_finish(local_id);
            return;
        }
        let appended = match appended {
            Ok(appended) => appended,
            Err(error) => {
                if runtime_is_cancelled(local_id) {
                    finish_cancelled_upload(
                        center,
                        session,
                        &authenticated,
                        auth_generation,
                        account_id,
                        local_id,
                        Some(transfer_id),
                    )
                    .await;
                } else {
                    handle_upload_error(
                        center,
                        session,
                        auth_generation,
                        account_id,
                        local_id,
                        error,
                    );
                }
                return;
            }
        };
        if appended.next_offset != end || appended.next_offset > size {
            fail_upload(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                "The server returned an unexpected upload offset. Restart to avoid mixing content."
                    .to_owned(),
                true,
            );
            return;
        }
        offset = appended.next_offset;
        save_resume(
            &appended.transfer,
            last_modified_ms,
            offset,
            bot_id,
            bot_auto,
        );
        center.record_transfer(appended.transfer.clone());
        update_queued(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            |item| {
                item.transferred = offset;
                item.phase = UploadPhase::Uploading;
            },
        );
    }

    if runtime_is_cancelled(local_id) {
        finish_cancelled_upload(
            center,
            session,
            &authenticated,
            auth_generation,
            account_id,
            local_id,
            Some(transfer_id),
        )
        .await;
        return;
    }
    update_queued(
        center,
        session,
        auth_generation,
        account_id,
        local_id,
        |item| item.phase = UploadPhase::Publishing,
    );
    let signal = runtime_signal(local_id);
    let completed =
        api::complete_upload(transfer_id, &authenticated.csrf_token, signal.as_ref()).await;
    runtime_clear_controller(local_id);
    if !session.is_current(auth_generation, account_id) {
        runtime_finish(local_id);
        return;
    }
    if runtime_is_cancelled(local_id) {
        finish_cancelled_upload(
            center,
            session,
            &authenticated,
            auth_generation,
            account_id,
            local_id,
            Some(transfer_id),
        )
        .await;
        return;
    }
    match completed {
        Ok(completed) => {
            transfer_store::remove(transfer_id);
            center.upload_completed(completed.transfer);
            update_queued(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                |item| {
                    item.phase = UploadPhase::Completed;
                    item.transferred = size;
                    item.error = None;
                },
            );
            runtime_finish(local_id);
        }
        Err(error) => {
            handle_upload_error(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                error,
            );
        }
    }
}

struct ProtectedStart {
    session_id: String,
    remote_name: String,
    complete_header: String,
    ciphertext_len: u64,
    chunk_size: u64,
    staged_len: u64,
}

#[allow(clippy::too_many_arguments)]
async fn run_protected_upload(
    center: TransferCenterState,
    session: SessionState,
    local_id: Uuid,
    file: File,
    folder_id: Option<String>,
    force_restart: bool,
    protection: UploadProtection,
    bot_id: Option<Uuid>,
    bot_auto: bool,
) {
    let UploadProtection::Protected(credential) = protection else {
        return;
    };
    let Some(authenticated) = current_session(session) else {
        runtime_finish(local_id);
        return;
    };
    let Some(encryption) = runtime_encryption(local_id) else {
        runtime_finish(local_id);
        return;
    };
    let auth_generation = session.generation.get_untracked();
    let account_id = authenticated.account.id;
    let account = account_id.to_string();
    let original_name = file.name().trim().to_owned();
    let mime_type = match file.type_().trim() {
        "" => "application/octet-stream".to_owned(),
        value => value.to_owned(),
    };
    let plaintext_len = file.size() as u64;
    let last_modified_ms = file.last_modified() as i64;
    let original_id = format!(
        "{}:{}:{}:{}",
        plaintext_len,
        last_modified_ms,
        folder_id.as_deref().unwrap_or("root"),
        bot_id.map(|id| id.to_string()).unwrap_or_else(|| {
            if bot_auto {
                "auto".to_string()
            } else {
                "personal".to_string()
            }
        })
    );
    let job_id = local_id.to_string();

    if force_restart {
        let _ = encryption
            .request_success(Command::Cancel {
                account_id: None,
                job_id: Some(job_id.clone()),
            })
            .await;
        let _ = encryption
            .request_with_id(
                job_id.clone(),
                Command::JournalDelete {
                    account_id: account.clone(),
                    original_id: original_id.clone(),
                },
            )
            .await;
    }
    let journal = if force_restart {
        None
    } else {
        match encryption
            .request_with_id(
                job_id.clone(),
                Command::JournalLoad {
                    account_id: account.clone(),
                    original_id: original_id.clone(),
                },
            )
            .await
        {
            Ok(success) => match success.result {
                JobResult::Journal { journal } => journal,
                _ => None,
            },
            Err(message) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    false,
                );
                return;
            }
        }
    };

    let mut verification_hash = None;
    let mut verified_plaintext_offset = 0_u64;
    let mut start = if let Some(journal) = &journal {
        update_queued(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            |item| {
                item.phase = UploadPhase::Verifying;
                item.transfer_id = Uuid::parse_str(&journal.remote_id).ok();
                item.transferred = 0;
            },
        );
        match protected_start(
            &encryption,
            &job_id,
            &account,
            &original_name,
            &mime_type,
            plaintext_len,
            &credential,
            Some(journal),
        )
        .await
        {
            Ok(start) => start,
            Err(message) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    true,
                );
                return;
            }
        }
    } else {
        match protected_start(
            &encryption,
            &job_id,
            &account,
            &original_name,
            &mime_type,
            plaintext_len,
            &credential,
            None,
        )
        .await
        {
            Ok(start) => start,
            Err(message) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    false,
                );
                return;
            }
        }
    };

    if journal.is_some() {
        match verify_staged_prefix(&encryption, &job_id, &account, &file, &start).await {
            Ok((hash, plaintext_offset)) => {
                verification_hash = Some(hash);
                verified_plaintext_offset = plaintext_offset;
            }
            Err(message) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    true,
                );
                return;
            }
        }
    }

    if runtime_is_cancelled(local_id) {
        finish_cancelled_upload(
            center,
            session,
            &authenticated,
            auth_generation,
            account_id,
            local_id,
            journal
                .as_ref()
                .and_then(|journal| Uuid::parse_str(&journal.remote_id).ok()),
        )
        .await;
        return;
    }

    let request = CreateUploadRequest {
        name: start.remote_name.clone(),
        folder_id: folder_id.clone(),
        size: start.ciphertext_len,
        mime_type: "application/octet-stream".to_owned(),
        source_modified_ms: Some(last_modified_ms),
        prefix_sha256: verification_hash.clone(),
        protected: true,
        bot_id,
        bot_auto,
    };
    let signal = runtime_signal(local_id);
    let created = api::create_upload(&request, &authenticated.csrf_token, signal.as_ref()).await;
    runtime_clear_controller(local_id);
    if !session.is_current(auth_generation, account_id) {
        runtime_finish(local_id);
        return;
    }
    let upload = match created {
        Ok(upload) => upload,
        Err(error) => {
            handle_upload_error(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                error,
            );
            return;
        }
    };
    let transfer_id = upload.transfer.id;
    if upload.transfer.size != start.ciphertext_len
        || upload.next_offset != start.staged_len
        || journal
            .as_ref()
            .is_some_and(|journal| Uuid::parse_str(&journal.remote_id).ok() != Some(transfer_id))
    {
        fail_upload(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            "The protected staged offset could not be confirmed. Restart with fresh encryption."
                .to_owned(),
            true,
        );
        return;
    }

    if journal.is_none() {
        let header = match BASE64.decode(&start.complete_header) {
            Ok(header) => Uint8Array::from(header.as_slice()),
            Err(_) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    "The worker returned an invalid protected header.".to_owned(),
                    false,
                );
                return;
            }
        };
        let header_len = u64::from(header.length());
        match append_protected_chunk(local_id, transfer_id, 0, header, &authenticated.csrf_token)
            .await
        {
            Ok(response) if response.next_offset == header_len => {
                start.staged_len = response.next_offset;
            }
            Ok(_) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    "The protected header offset was not accepted.".to_owned(),
                    true,
                );
                return;
            }
            Err(error) => {
                handle_upload_error(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    error,
                );
                return;
            }
        }
    }

    center.record_transfer(upload.transfer.clone());
    update_queued(
        center,
        session,
        auth_generation,
        account_id,
        local_id,
        |item| {
            item.transfer_id = Some(transfer_id);
            item.phase = UploadPhase::Uploading;
            item.ciphertext_size = Some(start.ciphertext_len);
            item.ciphertext_transferred = Some(start.staged_len);
            item.error = None;
        },
    );
    let mut current_journal = ContinuationJournal {
        account_id: account.clone(),
        original_id: original_id.clone(),
        remote_id: transfer_id.to_string(),
        bot_id: bot_id.map(|id| id.to_string()),
        complete_header: start.complete_header.clone(),
        next_offset: start.staged_len,
        source_sha256: journal
            .as_ref()
            .and_then(|journal| journal.source_sha256.clone()),
        staged_ciphertext_sha256: verification_hash.clone(),
    };
    if let Err(message) = save_protected_journal(&encryption, &job_id, &current_journal).await {
        fail_upload(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            message,
            false,
        );
        return;
    }

    let mut plaintext_offset = verified_plaintext_offset;
    while plaintext_offset < plaintext_len {
        if runtime_is_cancelled(local_id) {
            delete_protected_journal(&encryption, &job_id, &current_journal).await;
            finish_cancelled_upload(
                center,
                session,
                &authenticated,
                auth_generation,
                account_id,
                local_id,
                Some(transfer_id),
            )
            .await;
            return;
        }
        let end = plaintext_offset
            .saturating_add(start.chunk_size)
            .min(plaintext_len);
        let plaintext = match transfer_store::read_chunk(&file, plaintext_offset, end).await {
            Ok(bytes) => BASE64.encode(bytes.to_vec()),
            Err(message) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    false,
                );
                return;
            }
        };
        let record = match encryption
            .request_with_id(
                job_id.clone(),
                Command::EncryptionNext {
                    account_id: account.clone(),
                    session_id: start.session_id.clone(),
                    plaintext: plaintext.into(),
                },
            )
            .await
        {
            Ok(success) => match success.result {
                JobResult::EncryptionRecord {
                    plaintext_offset: actual_plaintext,
                    next_plaintext_offset,
                    ciphertext_offset,
                    next_ciphertext_offset,
                    ciphertext,
                    ..
                } => (
                    actual_plaintext,
                    next_plaintext_offset,
                    ciphertext_offset,
                    next_ciphertext_offset,
                    ciphertext,
                ),
                _ => {
                    fail_upload(
                        center,
                        session,
                        auth_generation,
                        account_id,
                        local_id,
                        "The worker returned an unexpected encryption record.".to_owned(),
                        false,
                    );
                    return;
                }
            },
            Err(message) => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    false,
                );
                return;
            }
        };
        if record.0 != plaintext_offset
            || record.1 != end
            || record.3 > start.ciphertext_len
            || record.2 > start.ciphertext_len
        {
            fail_upload(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                "The protected record offsets were inconsistent.".to_owned(),
                true,
            );
            return;
        }
        if record.2 >= start.staged_len {
            let ciphertext = match BASE64.decode(&record.4) {
                Ok(ciphertext) => Uint8Array::from(ciphertext.as_slice()),
                Err(_) => {
                    fail_upload(
                        center,
                        session,
                        auth_generation,
                        account_id,
                        local_id,
                        "The worker returned invalid ciphertext.".to_owned(),
                        false,
                    );
                    return;
                }
            };
            match append_protected_chunk(
                local_id,
                transfer_id,
                record.2,
                ciphertext,
                &authenticated.csrf_token,
            )
            .await
            {
                Ok(response) if response.next_offset == record.3 => {
                    center.record_transfer(response.transfer);
                }
                Ok(_) => {
                    fail_upload(
                        center,
                        session,
                        auth_generation,
                        account_id,
                        local_id,
                        "The protected ciphertext offset was not accepted.".to_owned(),
                        true,
                    );
                    return;
                }
                Err(error) => {
                    handle_upload_error(
                        center,
                        session,
                        auth_generation,
                        account_id,
                        local_id,
                        error,
                    );
                    return;
                }
            }
            current_journal.next_offset = record.3;
            if let Err(message) =
                save_protected_journal(&encryption, &job_id, &current_journal).await
            {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    message,
                    false,
                );
                return;
            }
        }
        plaintext_offset = end;
        update_queued(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            |item| {
                item.transferred = plaintext_offset;
                item.ciphertext_transferred = Some(record.3.max(start.staged_len));
            },
        );
    }

    let finished = match encryption
        .request_with_id(
            job_id.clone(),
            Command::EncryptionFinish {
                account_id: account.clone(),
                session_id: start.session_id.clone(),
            },
        )
        .await
    {
        Ok(success) => match success.result {
            JobResult::EncryptionFinished {
                final_record,
                ciphertext_offset,
                ciphertext_len,
                plaintext_sha256,
                staged_ciphertext_sha256,
                ..
            } => (
                final_record,
                ciphertext_offset,
                ciphertext_len,
                plaintext_sha256,
                staged_ciphertext_sha256,
            ),
            _ => {
                fail_upload(
                    center,
                    session,
                    auth_generation,
                    account_id,
                    local_id,
                    "The worker returned an unexpected encryption finish result.".to_owned(),
                    false,
                );
                return;
            }
        },
        Err(message) => {
            fail_upload(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                message,
                false,
            );
            return;
        }
    };
    if finished.2 != start.ciphertext_len
        || finished.4 != verification_hash
        || current_journal
            .source_sha256
            .as_ref()
            .is_some_and(|expected| expected != &finished.3)
    {
        fail_upload(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            "Protected source or staged-ciphertext verification failed. Restart with fresh encryption."
                .to_owned(),
            true,
        );
        return;
    }
    current_journal.source_sha256 = Some(finished.3);
    current_journal.staged_ciphertext_sha256 = finished.4;
    let final_record = match BASE64.decode(&finished.0) {
        Ok(record) => Uint8Array::from(record.as_slice()),
        Err(_) => {
            fail_upload(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                "The worker returned an invalid final record.".to_owned(),
                false,
            );
            return;
        }
    };
    match append_protected_chunk(
        local_id,
        transfer_id,
        finished.1,
        final_record,
        &authenticated.csrf_token,
    )
    .await
    {
        Ok(response) if response.next_offset == start.ciphertext_len => {
            center.record_transfer(response.transfer);
        }
        Ok(_) => {
            fail_upload(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                "The protected final offset was not accepted.".to_owned(),
                true,
            );
            return;
        }
        Err(error) => {
            handle_upload_error(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                error,
            );
            return;
        }
    }
    current_journal.next_offset = start.ciphertext_len;
    let _ = save_protected_journal(&encryption, &job_id, &current_journal).await;

    update_queued(
        center,
        session,
        auth_generation,
        account_id,
        local_id,
        |item| item.phase = UploadPhase::Publishing,
    );
    match api::complete_upload(transfer_id, &authenticated.csrf_token, None).await {
        Ok(completed) => {
            delete_protected_journal(&encryption, &job_id, &current_journal).await;
            center.upload_completed(completed.transfer);
            update_queued(
                center,
                session,
                auth_generation,
                account_id,
                local_id,
                |item| {
                    item.phase = UploadPhase::Completed;
                    item.transferred = plaintext_len;
                    item.ciphertext_transferred = Some(start.ciphertext_len);
                    item.error = None;
                },
            );
            runtime_finish(local_id);
        }
        Err(error) => handle_upload_error(
            center,
            session,
            auth_generation,
            account_id,
            local_id,
            error,
        ),
    }
}

fn parse_protected_start(result: JobResult, staged_len: u64) -> Result<ProtectedStart, String> {
    match result {
        JobResult::EncryptionStarted {
            session_id,
            remote_name,
            complete_header,
            ciphertext_len,
            plaintext_chunk_size,
            ..
        } => Ok(ProtectedStart {
            session_id,
            remote_name,
            complete_header,
            ciphertext_len,
            chunk_size: u64::from(plaintext_chunk_size),
            staged_len,
        }),
        _ => Err("The worker returned an unexpected encryption start result.".to_owned()),
    }
}

#[allow(clippy::too_many_arguments)]
async fn protected_start(
    encryption: &EncryptionContext,
    job_id: &str,
    account: &str,
    original_name: &str,
    mime_type: &str,
    plaintext_len: u64,
    credential: &Rc<CredentialMode>,
    journal: Option<&ContinuationJournal>,
) -> Result<ProtectedStart, String> {
    let staged_len = journal.map(|journal| journal.next_offset).unwrap_or(0);
    let command = if let Some(journal) = journal {
        Command::EncryptionContinue {
            account_id: account.to_owned(),
            original_name: original_name.to_owned(),
            mime_type: mime_type.to_owned(),
            total_plaintext_len: plaintext_len,
            complete_header: journal.complete_header.clone(),
            staged_ciphertext_len: staged_len,
            credential: duplicate_credential(credential),
        }
    } else {
        Command::EncryptionStart {
            account_id: account.to_owned(),
            original_name: original_name.to_owned(),
            mime_type: mime_type.to_owned(),
            total_plaintext_len: plaintext_len,
            credential: duplicate_credential(credential),
        }
    };
    let success = encryption
        .request_with_id(job_id.to_owned(), command)
        .await?;
    parse_protected_start(success.result, staged_len)
}

fn duplicate_credential(credential: &Rc<CredentialMode>) -> CredentialMode {
    match credential.as_ref() {
        CredentialMode::Passphrase { passphrase } => CredentialMode::Passphrase {
            passphrase: SecretString::from(passphrase.expose()),
        },
        CredentialMode::UnlockedVault => CredentialMode::UnlockedVault,
    }
}

async fn verify_staged_prefix(
    encryption: &EncryptionContext,
    job_id: &str,
    account: &str,
    file: &File,
    start: &ProtectedStart,
) -> Result<(String, u64), String> {
    let mut plaintext_offset = 0_u64;
    let total = file.size() as u64;
    let header_len = BASE64
        .decode(&start.complete_header)
        .map(|header| header.len() as u64)
        .unwrap_or(0);
    while plaintext_offset < total && start.staged_len > header_len {
        let end = plaintext_offset.saturating_add(start.chunk_size).min(total);
        let plaintext = transfer_store::read_chunk(file, plaintext_offset, end)
            .await
            .map(|bytes| BASE64.encode(bytes.to_vec()))?;
        let success = encryption
            .request_with_id(
                job_id.to_owned(),
                Command::EncryptionNext {
                    account_id: account.to_owned(),
                    session_id: start.session_id.clone(),
                    plaintext: plaintext.into(),
                },
            )
            .await?;
        let JobResult::EncryptionRecord {
            next_plaintext_offset,
            next_ciphertext_offset,
            ..
        } = success.result
        else {
            return Err("The worker returned an unexpected replay record.".to_owned());
        };
        if next_plaintext_offset != end || next_ciphertext_offset > start.staged_len {
            return Err("The source no longer matches the protected staged prefix.".to_owned());
        }
        plaintext_offset = end;
        if next_ciphertext_offset == start.staged_len {
            break;
        }
    }
    let success = encryption
        .request_with_id(
            job_id.to_owned(),
            Command::EncryptionCheckpoint {
                account_id: account.to_owned(),
                session_id: start.session_id.clone(),
            },
        )
        .await?;
    match success.result {
        JobResult::EncryptionCheckpoint {
            staged_ciphertext_sha256: Some(hash),
            ..
        } => Ok((hash, plaintext_offset)),
        _ => Err("The worker could not verify the staged ciphertext hash.".to_owned()),
    }
}

async fn append_protected_chunk(
    local_id: Uuid,
    transfer_id: Uuid,
    offset: u64,
    bytes: Uint8Array,
    csrf_token: &str,
) -> Result<salvage_protocol::UploadResponse, ApiError> {
    let signal = runtime_signal(local_id);
    let result = append_chunk(transfer_id, offset, bytes, csrf_token, signal.as_ref()).await;
    runtime_clear_controller(local_id);
    result
}

async fn save_protected_journal(
    encryption: &EncryptionContext,
    job_id: &str,
    journal: &ContinuationJournal,
) -> Result<(), String> {
    encryption
        .request_with_id(
            job_id.to_owned(),
            Command::JournalSave {
                journal: journal.clone(),
            },
        )
        .await
        .map(|_| ())
}

async fn delete_protected_journal(
    encryption: &EncryptionContext,
    job_id: &str,
    journal: &ContinuationJournal,
) {
    let _ = encryption
        .request_with_id(
            job_id.to_owned(),
            Command::JournalDelete {
                account_id: journal.account_id.clone(),
                original_id: journal.original_id.clone(),
            },
        )
        .await;
}

async fn append_chunk(
    transfer_id: Uuid,
    offset: u64,
    bytes: Uint8Array,
    csrf_token: &str,
    signal: Option<&AbortSignal>,
) -> Result<salvage_protocol::UploadResponse, ApiError> {
    api::append_upload_chunk(transfer_id, offset, bytes, csrf_token, signal).await
}

fn save_resume(
    transfer: &Transfer,
    last_modified_ms: i64,
    next_offset: u64,
    bot_id: Option<Uuid>,
    bot_auto: bool,
) {
    transfer_store::save(ResumeMetadata::new(
        transfer.id,
        transfer.name.clone(),
        transfer.size,
        last_modified_ms,
        transfer.folder_id.clone(),
        bot_id,
        bot_auto,
        next_offset,
    ));
}

fn handle_upload_error(
    center: TransferCenterState,
    session: SessionState,
    auth_generation: u64,
    account_id: Uuid,
    local_id: Uuid,
    error: ApiError,
) {
    if error.is_unauthorized() {
        session.expire(auth_generation, account_id);
        runtime_finish(local_id);
        return;
    }
    let conflict = error.is_conflict();
    fail_upload(
        center,
        session,
        auth_generation,
        account_id,
        local_id,
        error.message,
        conflict,
    );
}

fn fail_upload(
    center: TransferCenterState,
    session: SessionState,
    auth_generation: u64,
    account_id: Uuid,
    local_id: Uuid,
    message: String,
    conflict: bool,
) {
    runtime_clear_controller(local_id);
    update_queued(
        center,
        session,
        auth_generation,
        account_id,
        local_id,
        |item| {
            item.phase = if conflict {
                UploadPhase::Conflict
            } else {
                UploadPhase::Failed
            };
            item.error = Some(message);
        },
    );
}

async fn finish_cancelled_upload(
    center: TransferCenterState,
    session: SessionState,
    authenticated: &SessionResponse,
    auth_generation: u64,
    account_id: Uuid,
    local_id: Uuid,
    transfer_id: Option<Uuid>,
) {
    if let Some(transfer_id) = transfer_id {
        let result = api::cancel_transfer(transfer_id, &authenticated.csrf_token).await;
        if !session.is_current(auth_generation, account_id) {
            runtime_finish(local_id);
            return;
        }
        match result {
            Ok(transfer) => center.record_transfer(transfer),
            Err(error) if error.status == Some(404) => {}
            Err(error) if error.is_unauthorized() => {
                session.expire(auth_generation, account_id);
                runtime_finish(local_id);
                return;
            }
            Err(error) => {
                center.queue_cancelling.set(None);
                update_queued_unguarded(center, local_id, |item| {
                    item.phase = UploadPhase::Failed;
                    item.error = Some(format!(
                        "Cancellation couldn’t be confirmed. Refresh and try again. {}",
                        error.message
                    ));
                });
                runtime_finish(local_id);
                return;
            }
        }
        transfer_store::remove(transfer_id);
    }
    if session.is_current(auth_generation, account_id) {
        center.queue_cancelling.set(None);
        update_queued_unguarded(center, local_id, |item| {
            item.phase = UploadPhase::Cancelled;
            item.error = None;
        });
    }
    runtime_finish(local_id);
}

#[allow(clippy::too_many_arguments)]
async fn cancel_inactive_upload(
    center: TransferCenterState,
    session: SessionState,
    authenticated: SessionResponse,
    auth_generation: u64,
    account_id: Uuid,
    local_id: Uuid,
    transfer_id: Option<Uuid>,
) {
    finish_cancelled_upload(
        center,
        session,
        &authenticated,
        auth_generation,
        account_id,
        local_id,
        transfer_id,
    )
    .await;
}

fn update_queued(
    center: TransferCenterState,
    session: SessionState,
    auth_generation: u64,
    account_id: Uuid,
    local_id: Uuid,
    update: impl FnOnce(&mut QueuedUpload),
) {
    if session.is_current(auth_generation, account_id) {
        update_queued_unguarded(center, local_id, update);
    }
}

fn update_queued_unguarded(
    center: TransferCenterState,
    local_id: Uuid,
    update: impl FnOnce(&mut QueuedUpload),
) {
    center.queue.update(|queue| {
        if let Some(item) = queue.iter_mut().find(|item| item.local_id == local_id) {
            update(item);
        }
    });
}

fn queued_item(center: TransferCenterState, local_id: Uuid) -> Option<QueuedUpload> {
    center
        .queue
        .get_untracked()
        .into_iter()
        .find(|item| item.local_id == local_id)
}

fn current_session(session: SessionState) -> Option<SessionResponse> {
    match session.status.get_untracked() {
        SessionStatus::Authenticated(authenticated) => Some(authenticated),
        _ => None,
    }
}

fn can_cancel(status: TransferStatus) -> bool {
    matches!(
        status,
        TransferStatus::Staging
            | TransferStatus::Publishing
            | TransferStatus::Ready
            | TransferStatus::Failed
    )
}

fn status_label(transfer: &Transfer) -> &'static str {
    match transfer.status {
        TransferStatus::Staging if transfer.direction == TransferDirection::Upload => {
            "Resume available"
        }
        TransferStatus::Staging => "Staging",
        TransferStatus::Publishing if transfer.direction == TransferDirection::Upload => {
            "Publishing"
        }
        TransferStatus::Publishing => "Preparing download",
        TransferStatus::Ready => "Ready to download",
        TransferStatus::Completed => "Completed",
        TransferStatus::Failed => "Failed",
        TransferStatus::Cancelled => "Cancelled",
    }
}

fn progress_percent(transferred: u64, size: u64, complete: bool) -> u64 {
    if complete {
        100
    } else if size == 0 {
        0
    } else {
        transferred
            .saturating_mul(100)
            .checked_div(size)
            .unwrap_or(0)
            .min(100)
    }
}

fn format_size(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    let bytes = bytes as f64;
    if bytes < KIB {
        format!("{} B", bytes as u64)
    } else if bytes < KIB * KIB {
        format!("{:.1} KB", bytes / KIB)
    } else if bytes < KIB * KIB * KIB {
        format!("{:.1} MB", bytes / (KIB * KIB))
    } else {
        format!("{:.1} GB", bytes / (KIB * KIB * KIB))
    }
}
