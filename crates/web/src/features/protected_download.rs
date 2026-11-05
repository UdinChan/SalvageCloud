use leptos::prelude::*;
use leptos::task::spawn_local;
use salvage_crypto_worker::{Command, CredentialMode, JobResult};
use uuid::Uuid;

use crate::api;
use crate::components::{Dialog, Icon, IconName, Spinner};
use crate::encryption::{EncryptionContext, save_decrypted_file};
use crate::features::transfers::TransferCenterState;
use crate::state::{SessionState, SessionStatus};

#[derive(Clone, Copy)]
struct DownloadDialogState {
    open: RwSignal<bool>,
    busy: RwSignal<bool>,
    error: RwSignal<Option<String>>,
    passphrase: RwSignal<String>,
    generation: RwSignal<u64>,
}

impl DownloadDialogState {
    fn new() -> Self {
        Self {
            open: RwSignal::new(false),
            busy: RwSignal::new(false),
            error: RwSignal::new(None),
            passphrase: RwSignal::new(String::new()),
            generation: RwSignal::new(0),
        }
    }
}

#[component]
pub fn ProtectedDownloadAction(
    #[prop(optional)] file_id: Option<String>,
    transfer_id: Uuid,
    expected_ciphertext_len: u64,
    #[prop(into)] name: String,
    request_generation: RwSignal<u64>,
) -> impl IntoView {
    let session = expect_context::<SessionState>();
    let encryption = expect_context::<EncryptionContext>();
    let transfer_center = expect_context::<TransferCenterState>();
    let state = DownloadDialogState::new();
    let job_id = Uuid::new_v4().to_string();
    let download_label = format!("Download {name}");
    let dialog_title = format!("Decrypt {name}");
    let file_id_for_passphrase = file_id.clone();
    let job_id_for_close = job_id.clone();
    let job_id_for_passphrase = job_id.clone();

    let open_dialog = move |_| {
        state
            .generation
            .update(|generation| *generation = generation.wrapping_add(1));
        state.open.set(true);
        state.busy.set(false);
        state.error.set(None);
        state.passphrase.set(String::new());
    };
    let close_dialog: Callback<()> = Callback::new(move |_: ()| {
        state
            .generation
            .update(|generation| *generation = generation.wrapping_add(1));
        encryption.cancel_job(job_id_for_close.clone());
        state.open.set(false);
        state.busy.set(false);
        state.passphrase.set(String::new());
    });

    let use_passphrase: Callback<()> = Callback::new(move |_: ()| {
        begin_protected_download(
            session,
            encryption,
            transfer_center,
            state,
            request_generation,
            file_id_for_passphrase.clone(),
            transfer_id,
            expected_ciphertext_len,
            job_id_for_passphrase.clone(),
            false,
        );
    });
    let use_vault: Callback<()> = Callback::new(move |_: ()| {
        begin_protected_download(
            session,
            encryption,
            transfer_center,
            state,
            request_generation,
            file_id.clone(),
            transfer_id,
            expected_ciphertext_len,
            job_id.clone(),
            true,
        );
    });

    view! {
        <button class="icon-button" type="button" aria-label=download_label title="Download and decrypt file" on:click=open_dialog>
            <Icon icon=IconName::Download size=18/>
        </button>
        <Show when=move || state.open.get()>
            <Dialog title=dialog_title.clone() description="Choose a per-file passphrase or the account’s unlocked vault. Original metadata is recovered only after authentication.".to_owned() on_close=close_dialog>
                <div class="protected-download-dialog">
                    <div class="share-warning"><Icon icon=IconName::Lock size=18/><p>"The generic .tdenc2 file is decrypted inside the dedicated worker. No plaintext is sent to the server."</p></div>
                    {move || state.error.get().map(|message| view! {
                        <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div>
                    })}
                    <label for="protected-download-passphrase">"Passphrase"</label>
                    <input id="protected-download-passphrase" type="password" autocomplete="off" prop:value=move || state.passphrase.get() on:input=move |event| state.passphrase.set(event_target_value(&event))/>
                    <div class="protected-credential-actions">
                        <button class="button button-primary" type="button" disabled=move || state.busy.get() on:click=move |_| use_passphrase.run(())><Icon icon=IconName::Lock size=17/>"Use passphrase"</button>
                        <button class="button button-secondary" type="button" disabled=move || state.busy.get() on:click=move |_| use_vault.run(())>
                            <Icon icon=IconName::Shield size=17/>
                            {move || if encryption.vault_unlocked() { "Use unlocked vault" } else { "Unlock vault" }}
                        </button>
                    </div>
                    <Show when=move || state.busy.get()>
                        <div class="vault-busy" role="status"><Spinner size=18/><span>"Preparing, downloading, and authenticating the protected file…"</span></div>
                    </Show>
                    <p class="field-help">"Passphrases are used for this worker request and are never saved. Locking the vault or signing out cancels the operation."</p>
                </div>
            </Dialog>
        </Show>
    }
}

#[allow(clippy::too_many_arguments)]
fn begin_protected_download(
    session: SessionState,
    encryption: EncryptionContext,
    transfer_center: TransferCenterState,
    state: DownloadDialogState,
    request_generation: RwSignal<u64>,
    file_id: Option<String>,
    transfer_id: Uuid,
    expected_ciphertext_len: u64,
    job_id: String,
    use_vault: bool,
) {
    if state.busy.get_untracked() {
        return;
    }
    let Some(authenticated) = current_session(session) else {
        return;
    };
    let auth_generation = session.generation.get_untracked();
    let account_id = authenticated.account.id;
    let account = account_id.to_string();
    let own_request = request_generation.get_untracked();
    let own_generation = state.generation.get_untracked();
    let vault_unlocked = encryption.vault_unlocked();
    let passphrase = state.passphrase.get_untracked();
    if !use_vault && passphrase.is_empty() {
        state
            .error
            .set(Some("Enter the file’s passphrase.".to_owned()));
        return;
    }
    if use_vault && !vault_unlocked && passphrase.is_empty() {
        state
            .error
            .set(Some("Enter the vault passphrase to unlock it.".to_owned()));
        return;
    }
    state.passphrase.set(String::new());
    state.error.set(None);
    state.busy.set(true);

    spawn_local(async move {
        let credential = if use_vault {
            if !vault_unlocked {
                match encryption
                    .request_success(Command::VaultUnlock {
                        account_id: account.clone(),
                        passphrase: passphrase.into(),
                    })
                    .await
                {
                    Ok(success) => {
                        if !download_guard(
                            session,
                            state,
                            request_generation,
                            own_request,
                            own_generation,
                            auth_generation,
                            account_id,
                        ) {
                            return;
                        }
                        if let JobResult::Vault { vault } = success.result {
                            encryption.set_vault(vault);
                        }
                    }
                    Err(message) => {
                        finish_download_error(
                            session,
                            state,
                            request_generation,
                            own_request,
                            own_generation,
                            auth_generation,
                            account_id,
                            message,
                        );
                        return;
                    }
                }
            }
            CredentialMode::UnlockedVault
        } else {
            CredentialMode::Passphrase {
                passphrase: passphrase.into(),
            }
        };

        if !download_guard(
            session,
            state,
            request_generation,
            own_request,
            own_generation,
            auth_generation,
            account_id,
        ) {
            return;
        }

        let mut download_url = format!("/api/v1/transfers/{transfer_id}/content");
        let mut expected_len = expected_ciphertext_len;
        if let Some(file_id) = file_id.filter(|id| !id.is_empty()) {
            match api::prepare_download(&file_id, &authenticated.csrf_token).await {
                Ok(response) => {
                    if !download_guard(
                        session,
                        state,
                        request_generation,
                        own_request,
                        own_generation,
                        auth_generation,
                        account_id,
                    ) {
                        return;
                    }
                    expected_len = response.file.size;
                    download_url = response.download_url;
                    transfer_center.record_transfer(response.transfer);
                }
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                    return;
                }
                Err(error) => {
                    finish_download_error(
                        session,
                        state,
                        request_generation,
                        own_request,
                        own_generation,
                        auth_generation,
                        account_id,
                        error.message,
                    );
                    return;
                }
            }
        }

        let result = encryption
            .request_with_id(
                job_id,
                Command::DownloadDecrypt {
                    account_id: account,
                    url: download_url,
                    expected_ciphertext_len: expected_len,
                    credential,
                },
            )
            .await;
        if !download_guard(
            session,
            state,
            request_generation,
            own_request,
            own_generation,
            auth_generation,
            account_id,
        ) {
            return;
        }
        match result {
            Ok(success) => match success.result {
                JobResult::Downloaded { original_name, .. } => {
                    if let Some(file) = success.file {
                        match save_decrypted_file(&file, &original_name) {
                            Ok(()) => {
                                state.busy.set(false);
                                state.open.set(false);
                                state.passphrase.set(String::new());
                            }
                            Err(message) => finish_download_error(
                                session,
                                state,
                                request_generation,
                                own_request,
                                own_generation,
                                auth_generation,
                                account_id,
                                message,
                            ),
                        }
                    } else {
                        finish_download_error(
                            session,
                            state,
                            request_generation,
                            own_request,
                            own_generation,
                            auth_generation,
                            account_id,
                            "The worker did not return the authenticated plaintext file."
                                .to_owned(),
                        );
                    }
                }
                _ => finish_download_error(
                    session,
                    state,
                    request_generation,
                    own_request,
                    own_generation,
                    auth_generation,
                    account_id,
                    "The worker returned an unexpected download result.".to_owned(),
                ),
            },
            Err(message) => finish_download_error(
                session,
                state,
                request_generation,
                own_request,
                own_generation,
                auth_generation,
                account_id,
                message,
            ),
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn finish_download_error(
    session: SessionState,
    state: DownloadDialogState,
    request_generation: RwSignal<u64>,
    own_request: u64,
    own_generation: u64,
    auth_generation: u64,
    account_id: Uuid,
    message: String,
) {
    if download_guard(
        session,
        state,
        request_generation,
        own_request,
        own_generation,
        auth_generation,
        account_id,
    ) {
        state.busy.set(false);
        state.error.set(Some(message));
    }
}

fn download_guard(
    session: SessionState,
    state: DownloadDialogState,
    request_generation: RwSignal<u64>,
    own_request: u64,
    own_generation: u64,
    auth_generation: u64,
    account_id: Uuid,
) -> bool {
    session.is_current(auth_generation, account_id)
        && request_generation.get_untracked() == own_request
        && state.generation.get_untracked() == own_generation
        && state.open.get_untracked()
}

fn current_session(session: SessionState) -> Option<salvage_protocol::SessionResponse> {
    match session.status.get_untracked() {
        SessionStatus::Authenticated(authenticated) => Some(authenticated),
        _ => None,
    }
}
