use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use leptos::prelude::*;
use leptos::task::spawn_local;
use salvage_crypto_worker::{Command, JobResult, VaultInfo};
use uuid::Uuid;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Blob, BlobPropertyBag, Event, File, FilePropertyBag, HtmlInputElement};

use crate::components::{Icon, IconName, Spinner};
use crate::encryption::{EncryptionContext, EncryptionWorkerStatus};
use crate::state::{SessionState, SessionStatus};

#[component]
pub fn VaultSettings() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let encryption = expect_context::<EncryptionContext>();
    let passphrase = RwSignal::new(String::new());
    let recovery_export_passphrase = RwSignal::new(String::new());
    let recovery_passphrase = RwSignal::new(String::new());
    let new_vault_passphrase = RwSignal::new(String::new());
    let vault_container = RwSignal::new(String::new());
    let recovery_container = RwSignal::new(String::new());
    let replace_existing = RwSignal::new(false);
    let busy = RwSignal::new(Option::<&'static str>::None);
    let error = RwSignal::new(Option::<String>::None);
    let notice = RwSignal::new(Option::<String>::None);

    let account = move || {
        session
            .account()
            .map(|account| account.id.to_string())
            .unwrap_or_default()
    };
    let unlocked = move || {
        encryption.vault_unlocked()
            || notice.get().is_some_and(|message| {
                message.starts_with("Vault created")
                    || message.starts_with("Vault unlocked")
                    || message.starts_with("Recovery imported")
            })
    };

    let create_vault = move |_: ()| {
        let Some((auth_generation, account_id)) = operation_guard(session) else {
            return;
        };
        let secret = passphrase.get_untracked();
        if secret.is_empty() {
            error.set(Some("Enter a passphrase to create the vault.".to_owned()));
            return;
        }
        passphrase.set(String::new());
        busy.set(Some("Creating vault"));
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = encryption
                .request_success(Command::VaultCreate {
                    account_id: account_id.clone(),
                    passphrase: secret.into(),
                    profile_ids: Vec::new(),
                })
                .await;
            if !session.is_current(
                auth_generation,
                Uuid::parse_str(&account_id).unwrap_or_default(),
            ) {
                return;
            }
            busy.set(None);
            match result {
                Ok(success) => {
                    if let JobResult::VaultCreated { vault, .. } = success.result {
                        encryption.set_vault(vault);
                        notice.set(Some(
                            "Vault created. Its encrypted container is saved in IndexedDB."
                                .to_owned(),
                        ));
                    }
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let unlock_vault = move |_: ()| {
        let Some((auth_generation, account_id)) = operation_guard(session) else {
            return;
        };
        let secret = passphrase.get_untracked();
        if secret.is_empty() {
            error.set(Some("Enter the vault passphrase to unlock it.".to_owned()));
            return;
        }
        passphrase.set(String::new());
        busy.set(Some("Unlocking vault"));
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = encryption
                .request_success(Command::VaultUnlock {
                    account_id: account_id.clone(),
                    passphrase: secret.into(),
                })
                .await;
            if !session.is_current(
                auth_generation,
                Uuid::parse_str(&account_id).unwrap_or_default(),
            ) {
                return;
            }
            busy.set(None);
            match result {
                Ok(success) => {
                    if let JobResult::Vault { vault } = success.result {
                        encryption.set_vault(vault);
                        notice.set(Some("Vault unlocked in the encryption worker.".to_owned()));
                    }
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let open_vault = move |_: ()| {
        let Some((auth_generation, account_id)) = operation_guard(session) else {
            return;
        };
        let secret = passphrase.get_untracked();
        let container = vault_container.get_untracked();
        if secret.is_empty() || container.is_empty() {
            error.set(Some(
                "Choose an encrypted vault container and enter its passphrase.".to_owned(),
            ));
            return;
        }
        passphrase.set(String::new());
        busy.set(Some("Opening vault"));
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = encryption
                .request_success(Command::VaultOpen {
                    account_id: account_id.clone(),
                    container,
                    passphrase: secret.into(),
                })
                .await;
            if !session.is_current(
                auth_generation,
                Uuid::parse_str(&account_id).unwrap_or_default(),
            ) {
                return;
            }
            busy.set(None);
            match result {
                Ok(success) => {
                    if let JobResult::Vault { vault } = success.result {
                        encryption.set_vault(vault);
                        notice.set(Some("Encrypted vault opened and unlocked.".to_owned()));
                    }
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let lock_vault = move |_: ()| {
        let Some((auth_generation, account_id)) = operation_guard(session) else {
            return;
        };
        busy.set(Some("Locking vault"));
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = encryption.request_success(Command::Lock).await;
            if !session.is_current(
                auth_generation,
                Uuid::parse_str(&account_id).unwrap_or_default(),
            ) {
                return;
            }
            busy.set(None);
            match result {
                Ok(_) => {
                    encryption.set_vault(VaultInfo {
                        account_id,
                        unlocked: false,
                        created_at: None,
                        profile_ids: Vec::new(),
                    });
                    passphrase.set(String::new());
                    recovery_export_passphrase.set(String::new());
                    notice.set(Some(
                        "Vault locked. Unlocked keys and encryption sessions were dropped."
                            .to_owned(),
                    ));
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let export_recovery = move |_: ()| {
        let Some((auth_generation, account_id)) = operation_guard(session) else {
            return;
        };
        let secret = recovery_export_passphrase.get_untracked();
        if secret.is_empty() {
            error.set(Some(
                "Enter a recovery passphrase to encrypt the recovery file.".to_owned(),
            ));
            return;
        }
        recovery_export_passphrase.set(String::new());
        busy.set(Some("Exporting recovery"));
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = encryption
                .request_success(Command::RecoveryExport {
                    account_id: account_id.clone(),
                    passphrase: secret.into(),
                })
                .await;
            if !session.is_current(
                auth_generation,
                Uuid::parse_str(&account_id).unwrap_or_default(),
            ) {
                return;
            }
            busy.set(None);
            match result {
                Ok(success) => {
                    if let JobResult::RecoveryExported { container } = success.result {
                        match save_container(&container, "salvage-recovery.tdrec2") {
                            Ok(()) => notice.set(Some(
                                "Encrypted recovery file exported. Keep it and its recovery passphrase safe."
                                    .to_owned(),
                            )),
                            Err(message) => error.set(Some(message)),
                        }
                    }
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let import_recovery = move |_: ()| {
        let Some((auth_generation, account_id)) = operation_guard(session) else {
            return;
        };
        let recovery_secret = recovery_passphrase.get_untracked();
        let vault_secret = new_vault_passphrase.get_untracked();
        let container = recovery_container.get_untracked();
        if recovery_secret.is_empty() || vault_secret.is_empty() || container.is_empty() {
            error.set(Some(
                "Choose a recovery file and enter both recovery and new vault passphrases."
                    .to_owned(),
            ));
            return;
        }
        recovery_passphrase.set(String::new());
        new_vault_passphrase.set(String::new());
        busy.set(Some("Importing recovery"));
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = encryption
                .request_success(Command::RecoveryImport {
                    account_id: account_id.clone(),
                    container,
                    recovery_passphrase: recovery_secret.into(),
                    vault_passphrase: vault_secret.into(),
                    replace_existing: replace_existing.get_untracked(),
                })
                .await;
            if !session.is_current(
                auth_generation,
                Uuid::parse_str(&account_id).unwrap_or_default(),
            ) {
                return;
            }
            busy.set(None);
            match result {
                Ok(success) => {
                    if let JobResult::Vault { vault } = success.result {
                        encryption.set_vault(vault);
                        notice.set(Some(
                            "Recovery imported. The restored vault is encrypted in IndexedDB and unlocked."
                                .to_owned(),
                        ));
                    }
                }
                Err(message) => error.set(Some(message)),
            }
        });
    };

    let read_vault_container = move |event: Event| {
        read_container_input(event, session, vault_container, error);
    };
    let read_recovery_container = move |event: Event| {
        read_container_input(event, session, recovery_container, error);
    };

    view! {
        <section class="settings-card vault-settings" aria-labelledby="vault-heading">
            <div class="settings-card-heading">
                <span class="settings-card-icon"><Icon icon=IconName::Lock size=21/></span>
                <div><h3 id="vault-heading">"Encryption vault"</h3><p>"Unlock vault-backed encryption or use a separate passphrase for each protected file."</p></div>
            </div>

            <div class="vault-status" role="status">
                <span class=move || if unlocked() { "status-dot" } else { "status-dot status-dot-muted" }></span>
                <div>
                    <strong>{move || if unlocked() { "Vault unlocked" } else { "Vault locked" }}</strong>
                    <p>{move || match encryption.status() {
                        EncryptionWorkerStatus::Loading => "Loading the dedicated encryption worker…".to_owned(),
                        EncryptionWorkerStatus::Ready => format!("Account {} · Keys remain inside the worker while unlocked.", account()),
                        EncryptionWorkerStatus::Unavailable(message) => message,
                    }}</p>
                </div>
            </div>

            {move || error.get().map(|message| view! {
                <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div>
            })}
            {move || notice.get().map(|message| view! {
                <div class="inline-notice vault-notice" role="status"><Icon icon=IconName::Check size=17/><span>{message}</span></div>
            })}

            <div class="vault-primary-controls">
                <label for="vault-passphrase">"Vault passphrase"</label>
                <input id="vault-passphrase" type="password" autocomplete="current-password" prop:value=move || passphrase.get() on:input=move |event| passphrase.set(event_target_value(&event))/>
                <div class="vault-button-row">
                    <button class="button button-primary" type="button" disabled=move || busy.get().is_some() || unlocked() on:click=move |_| create_vault(())><Icon icon=IconName::Plus size=17/>"Create vault"</button>
                    <button class="button button-secondary" type="button" disabled=move || busy.get().is_some() || unlocked() on:click=move |_| unlock_vault(())><Icon icon=IconName::Lock size=17/>"Unlock vault"</button>
                    <button class="button button-secondary" type="button" disabled=move || busy.get().is_some() || !unlocked() on:click=move |_| lock_vault(())><Icon icon=IconName::Lock size=17/>"Lock vault"</button>
                </div>
            </div>

            <details class="vault-section">
                <summary>"Open an encrypted vault container"</summary>
                <div class="vault-section-body">
                    <label for="vault-container">"Vault container"</label>
                    <input id="vault-container" type="file" accept=".tdvlt2,application/octet-stream" on:change=read_vault_container/>
                    <button class="button button-secondary" type="button" disabled=move || busy.get().is_some() || unlocked() on:click=move |_| open_vault(())>"Open vault"</button>
                </div>
            </details>

            <details class="vault-section">
                <summary>"Export recovery"</summary>
                <div class="vault-section-body">
                    <p>"Exports an encrypted TDREC2 recovery container. It never contains a raw master key."</p>
                    <label for="recovery-export-passphrase">"Recovery passphrase"</label>
                    <input id="recovery-export-passphrase" type="password" autocomplete="new-password" prop:value=move || recovery_export_passphrase.get() on:input=move |event| recovery_export_passphrase.set(event_target_value(&event))/>
                    <button class="button button-secondary" type="button" disabled=move || busy.get().is_some() || !unlocked() on:click=move |_| export_recovery(())><Icon icon=IconName::Download size=17/>"Export recovery"</button>
                </div>
            </details>

            <details class="vault-section">
                <summary>"Import recovery"</summary>
                <div class="vault-section-body">
                    <label for="recovery-file">"Recovery file"</label>
                    <input id="recovery-file" type="file" accept=".tdrec2,application/octet-stream" on:change=read_recovery_container/>
                    <label for="recovery-passphrase">"Recovery passphrase"</label>
                    <input id="recovery-passphrase" type="password" autocomplete="off" prop:value=move || recovery_passphrase.get() on:input=move |event| recovery_passphrase.set(event_target_value(&event))/>
                    <label for="new-vault-passphrase">"New vault passphrase"</label>
                    <input id="new-vault-passphrase" type="password" autocomplete="new-password" prop:value=move || new_vault_passphrase.get() on:input=move |event| new_vault_passphrase.set(event_target_value(&event))/>
                    <label class="vault-checkbox"><input type="checkbox" checked=move || replace_existing.get() on:change=move |event| {
                        if let Some(input) = event.target().and_then(|target| target.dyn_into::<HtmlInputElement>().ok()) {
                            replace_existing.set(input.checked());
                        }
                    }/><span>"Replace an existing encrypted vault for this account"</span></label>
                    <button class="button button-secondary" type="button" disabled=move || busy.get().is_some() || unlocked() on:click=move |_| import_recovery(())><Icon icon=IconName::Upload size=17/>"Import recovery"</button>
                </div>
            </details>

            <p class="vault-privacy">"Only encrypted vault containers and name-free continuation journals are stored in IndexedDB. Passphrases, DEKs, master keys, plaintext, and original protected filenames are never persisted."</p>
            <Show when=move || busy.get().is_some()>
                <div class="vault-busy" role="status"><Spinner size=17/><span>{move || busy.get().unwrap_or("Working")}</span></div>
            </Show>
        </section>
    }
}

fn operation_guard(session: SessionState) -> Option<(u64, String)> {
    match session.status.get_untracked() {
        SessionStatus::Authenticated(authenticated) => Some((
            session.generation.get_untracked(),
            authenticated.account.id.to_string(),
        )),
        _ => None,
    }
}

fn read_container_input(
    event: Event,
    session: SessionState,
    destination: RwSignal<String>,
    error: RwSignal<Option<String>>,
) {
    let Some(file) = event
        .target()
        .and_then(|target| target.dyn_into::<HtmlInputElement>().ok())
        .and_then(|input| input.files())
        .and_then(|files| files.item(0))
    else {
        return;
    };
    let Some((generation, account_id)) = operation_guard(session) else {
        return;
    };
    spawn_local(async move {
        let result = JsFuture::from(file.array_buffer()).await;
        if !session.is_current(generation, Uuid::parse_str(&account_id).unwrap_or_default()) {
            return;
        }
        match result {
            Ok(value) => {
                let bytes = js_sys::Uint8Array::new(&value);
                destination.set(BASE64.encode(bytes.to_vec()));
                error.set(None);
            }
            Err(_) => error.set(Some("The encrypted container couldn’t be read.".to_owned())),
        }
    });
}

fn save_container(container: &str, name: &str) -> Result<(), String> {
    let bytes = BASE64
        .decode(container)
        .map_err(|_| "The encrypted recovery container is not valid base64.".to_owned())?;
    let parts = js_sys::Array::new();
    parts.push(&js_sys::Uint8Array::from(bytes.as_slice()));
    let blob_options = BlobPropertyBag::new();
    blob_options.set_type("application/octet-stream");
    let blob = Blob::new_with_str_sequence_and_options(&parts, &blob_options)
        .map_err(|_| "Couldn’t prepare the encrypted recovery file.".to_owned())?;
    let file_options = FilePropertyBag::new();
    file_options.set_type("application/octet-stream");
    let file =
        File::new_with_blob_sequence_and_options(&js_sys::Array::of1(&blob), name, &file_options)
            .map_err(|_| "Couldn’t prepare the encrypted recovery file.".to_owned())?;
    crate::encryption::save_decrypted_file(&file, name)
}
