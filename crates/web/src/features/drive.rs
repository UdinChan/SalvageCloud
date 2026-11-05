use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_params_map, use_query_map};
use salvage_protocol::{DriveFile, FileKind, FilePage, Folder, SessionResponse};

use crate::api::{self, ApiError};
use crate::components::{Dialog, EmptyState, ErrorState, Icon, IconName, Protected, Spinner};
use crate::features::transfers::TransferCenterState;
use crate::features::{FileActions, ProtectedDownloadAction};
use crate::state::{Preferences, SessionState, SessionStatus, ViewMode};

#[derive(Clone)]
struct DriveData {
    folders: Vec<Folder>,
    files: FilePage,
}

#[derive(Clone)]
enum LoadState {
    Loading,
    Ready(DriveData),
    Error(String),
}

#[component]
pub fn DrivePage() -> impl IntoView {
    view! { <Protected><DriveWorkspace/></Protected> }
}

#[component]
fn DriveWorkspace() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let preferences = expect_context::<Preferences>();
    let transfer_center = expect_context::<TransferCenterState>();
    let params = use_params_map();
    let query = use_query_map();
    let navigate = use_navigate();

    let load_state = RwSignal::new(LoadState::Loading);
    let request_generation = RwSignal::new(0_u64);
    let reload = RwSignal::new(0_u64);
    let search_input = RwSignal::new(String::new());

    let create_open = RwSignal::new(false);
    let rename_folder = RwSignal::new(Option::<Folder>::None);
    let delete_folder = RwSignal::new(Option::<Folder>::None);
    let folder_name = RwSignal::new(String::new());
    let action_pending = RwSignal::new(false);
    let action_error = RwSignal::new(Option::<String>::None);

    let folder_id = move || params.get().get("id");
    let search_query = move || query.get().get("q").unwrap_or_default().trim().to_owned();
    let base_path = move || match folder_id() {
        Some(id) => format!("/drive/folder/{id}"),
        None => "/drive".to_owned(),
    };
    let upload_path = move || match folder_id() {
        Some(id) => format!("/transfers?folder_id={}", encode_query(&id)),
        None => "/transfers".to_owned(),
    };

    Effect::new(move |_| {
        search_input.set(search_query());
    });

    Effect::new(move |_| {
        let parent_id = folder_id();
        let search = search_query();
        let _ = reload.get();
        let _ = transfer_center.drive_revision();
        let SessionStatus::Authenticated(authenticated) = session.status.get() else {
            return;
        };
        let account_id = authenticated.account.id;
        let auth_generation = session.generation.get_untracked();
        request_generation.update(|generation| *generation = generation.wrapping_add(1));
        let own_request = request_generation.get_untracked();
        load_state.set(LoadState::Loading);

        spawn_local(async move {
            let result = load_drive(parent_id.as_deref(), &search).await;
            if request_generation.get_untracked() != own_request
                || !session.is_current(auth_generation, account_id)
            {
                return;
            }
            match result {
                Ok(data) => load_state.set(LoadState::Ready(data)),
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id)
                }
                Err(error) => load_state.set(LoadState::Error(error.message)),
            }
        });
    });

    let submit_search = {
        let navigate = navigate.clone();
        move |_| {
            let value = search_input.get_untracked().trim().to_owned();
            let path = if value.is_empty() {
                base_path()
            } else {
                format!("{}?q={}", base_path(), encode_query(&value))
            };
            navigate(&path, Default::default());
            if value == search_query() {
                reload.update(|version| *version = version.wrapping_add(1));
            }
        }
    };

    let clear_search = move |_: ()| {
        search_input.set(String::new());
        navigate(&base_path(), Default::default());
        if search_query().is_empty() {
            reload.update(|version| *version = version.wrapping_add(1));
        }
    };
    let on_clear_search = Callback::new(clear_search);

    let open_create = move |_| {
        folder_name.set(String::new());
        action_error.set(None);
        create_open.set(true);
    };

    let create = move |_| {
        if action_pending.get_untracked() {
            return;
        }
        let name = folder_name.get_untracked().trim().to_owned();
        if name.is_empty() {
            action_error.set(Some("Give your folder a name.".to_owned()));
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let parent_id = folder_id();
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        action_pending.set(true);
        action_error.set(None);
        spawn_local(async move {
            let result =
                api::create_folder(&name, parent_id.as_deref(), &authenticated.csrf_token).await;
            let applied = handle_mutation_result(
                session,
                result.map(|_| ()),
                auth_generation,
                account_id,
                own_request,
                request_generation,
                action_pending,
                action_error,
                reload,
            );
            if applied {
                create_open.set(false);
                folder_name.set(String::new());
            }
        });
    };

    let rename = move |_| {
        if action_pending.get_untracked() {
            return;
        }
        let Some(folder) = rename_folder.get_untracked() else {
            return;
        };
        let name = folder_name.get_untracked().trim().to_owned();
        if name.is_empty() {
            action_error.set(Some("Give your folder a name.".to_owned()));
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        action_pending.set(true);
        action_error.set(None);
        spawn_local(async move {
            let result = api::rename_folder(&folder.id, &name, &authenticated.csrf_token).await;
            let applied = handle_mutation_result(
                session,
                result.map(|_| ()),
                auth_generation,
                account_id,
                own_request,
                request_generation,
                action_pending,
                action_error,
                reload,
            );
            if applied {
                rename_folder.set(None);
                folder_name.set(String::new());
            }
        });
    };

    let delete = move |_| {
        if action_pending.get_untracked() {
            return;
        }
        let Some(folder) = delete_folder.get_untracked() else {
            return;
        };
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        action_pending.set(true);
        action_error.set(None);
        spawn_local(async move {
            let result = api::delete_folder(&folder.id, &authenticated.csrf_token).await;
            let applied = handle_mutation_result(
                session,
                result,
                auth_generation,
                account_id,
                own_request,
                request_generation,
                action_pending,
                action_error,
                reload,
            );
            if applied {
                delete_folder.set(None);
            }
        });
    };

    let activate = move |folder: Folder| {
        if action_pending.get_untracked() {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        action_pending.set(true);
        action_error.set(None);
        spawn_local(async move {
            let result = api::activate_folder(&folder.id, &authenticated.csrf_token).await;
            let _ = handle_mutation_result(
                session,
                result.map(|_| ()),
                auth_generation,
                account_id,
                own_request,
                request_generation,
                action_pending,
                action_error,
                reload,
            );
        });
    };

    let close_dialog = move |_| {
        if !action_pending.get_untracked() {
            create_open.set(false);
            rename_folder.set(None);
            delete_folder.set(None);
            action_error.set(None);
        }
    };

    let heading = move || {
        if !search_query().is_empty() {
            "Search results".to_owned()
        } else if folder_id().is_some() {
            "Active channel".to_owned()
        } else {
            "My drive".to_owned()
        }
    };

    view! {
        <div class="drive-page">
            <nav class="breadcrumbs" aria-label="Breadcrumb">
                <A href="/drive"><Icon icon=IconName::Folder size=16/>"My drive"</A>
                {move || folder_id().map(|_| view! {
                    <Icon icon=IconName::ChevronRight size=14/>
                    <span aria-current="page">"Active channel"</span>
                })}
            </nav>

            <section class="drive-heading">
                <div>
                    <h2>{heading}</h2>
                    <p>{move || {
                        let search = search_query();
                        if search.is_empty() {
                            "A simple, organized home for everything you keep.".to_owned()
                        } else {
                            format!("Files matching “{search}” in this folder")
                        }
                    }}</p>
                </div>
                <div class="drive-heading-actions">
                    <button class="button button-secondary" type="button" aria-label="Sync channels" title="Discover and synchronize Telegram channels" on:click=move |_| reload.update(|version| *version = version.wrapping_add(1))>
                        <Icon icon=IconName::Refresh size=18/><span>"Sync channels"</span>
                    </button>
                    <A href=upload_path attr:class="button button-secondary upload-drive-button" attr:aria-label="Upload files"><Icon icon=IconName::Upload size=18/><span>"Upload files"</span></A>
                    <button class="button button-primary new-folder-button" type="button" on:click=move |_| open_create(())>
                        <Icon icon=IconName::Plus size=19/><span>"New channel"</span>
                    </button>
                </div>
            </section>

            <section class="drive-toolbar" aria-label="Drive controls">
                <form class="search-form" role="search" on:submit=move |event| { event.prevent_default(); submit_search(()); }>
                    <span class="search-icon"><Icon icon=IconName::Search size=19/></span>
                    <label class="sr-only" for="drive-search">"Search files in this folder"</label>
                    <input id="drive-search" type="search" placeholder="Search this folder…" autocomplete="off"
                        prop:value=move || search_input.get()
                        on:input=move |event| search_input.set(event_target_value(&event))
                    />
                    <Show when=move || !search_input.get().is_empty()>
                        <button class="search-clear" type="button" aria-label="Clear search" on:click=move |_| on_clear_search.run(())><Icon icon=IconName::Close size=17/></button>
                    </Show>
                    <button class="search-submit" type="submit">"Search"</button>
                </form>
                <div class="view-switcher" role="group" aria-label="Drive layout">
                    <button type="button" class=move || if preferences.value.get().view_mode == ViewMode::Grid { "is-active" } else { "" } aria-label="Grid view" aria-pressed=move || (preferences.value.get().view_mode == ViewMode::Grid).to_string() title="Grid view" on:click=move |_| preferences.set_view_mode(ViewMode::Grid)><Icon icon=IconName::Grid size=18/></button>
                    <button type="button" class=move || if preferences.value.get().view_mode == ViewMode::List { "is-active" } else { "" } aria-label="List view" aria-pressed=move || (preferences.value.get().view_mode == ViewMode::List).to_string() title="List view" on:click=move |_| preferences.set_view_mode(ViewMode::List)><Icon icon=IconName::List size=19/></button>
                </div>
            </section>

            {move || match load_state.get() {
                LoadState::Loading => view! { <DriveSkeleton/> }.into_any(),
                LoadState::Error(message) => view! {
                    <ErrorState title="Your drive didn’t load" message=message on_retry=Callback::new(move |_| reload.update(|version| *version = version.wrapping_add(1)))/>
                }.into_any(),
                LoadState::Ready(data) => {
                    let query = search_query().to_lowercase();
                    let folders: Vec<Folder> = data.folders.into_iter().filter(|folder| query.is_empty() || folder.name.to_lowercase().contains(&query)).collect();
                    let files = data.files;
                    if folders.is_empty() && files.files.is_empty() {
                        if search_query().is_empty() {
                            view! {
                                <EmptyState
                                    title="A fresh start"
                                    message="This folder is empty. Create a channel to begin organizing your drive."
                                    action_label="Create your first channel".to_owned()
                                    on_action=Callback::new(move |_| open_create(()))
                                />
                            }.into_any()
                        } else {
                            view! {
                                <EmptyState title="No matches here" message="Try a different file name or clear your search to see everything in this folder."/>
                            }.into_any()
                        }
                    } else {
                        view! {
                            <div class=move || if preferences.value.get().view_mode == ViewMode::Grid { "drive-entries is-grid" } else { "drive-entries is-list" }>
                                <Show when=move || preferences.value.get().view_mode == ViewMode::List>
                                    <div class="entry-list-header" aria-hidden="true"><span>"Name"</span><span>"Details"</span><span>"Actions"</span></div>
                                </Show>
                                <For
                                    each=move || folders.clone()
                                    key=|folder| folder.id.clone()
                                    children=move |folder| {
                                        let rename_target = folder.clone();
                                        let delete_target = folder.clone();
                                        let activate_target = folder.clone();
                                        let active = folder.active;
                                        let href = format!("/drive/folder/{}", folder.id);
                                        let display_name = folder.name.clone();
                                        let activate_label = format!("Set active {}", folder.name);
                                        let rename_label = format!("Rename {}", folder.name);
                                        let delete_label = format!("Delete {}", folder.name);
                                        view! {
                                            <article class="entry-card folder-card">
                                                <A href=href attr:class="entry-main">
                                                    <span class="entry-icon folder-icon"><Icon icon=IconName::Folder size=25/></span>
                                                    <span class="entry-copy">
                                                        <strong>{display_name}</strong>
                                                        {active.then(|| view! { <span class="protected-badge" title="Active upload channel">"Active"</span> })}
                                                        <span>{format_count(folder.file_count, "file")}</span>
                                                    </span>
                                                    <span class="folder-open-icon"><Icon icon=IconName::ChevronRight size=18/></span>
                                                </A>
                                                <div class="entry-actions">
                                                    {(!active).then(|| view! {
                                                        <button class="icon-button" type="button" aria-label=activate_label title="Set active upload channel" on:click=move |_| activate(activate_target.clone())><Icon icon=IconName::Check size=17/></button>
                                                    })}
                                                    <button class="icon-button" type="button" aria-label=rename_label title="Rename channel" on:click=move |_| {
                                                        folder_name.set(rename_target.name.clone());
                                                        action_error.set(None);
                                                        rename_folder.set(Some(rename_target.clone()));
                                                    }><Icon icon=IconName::Pencil size=17/></button>
                                                    <button class="icon-button danger-hover" type="button" aria-label=delete_label title="Delete channel" on:click=move |_| {
                                                        action_error.set(None);
                                                        delete_folder.set(Some(delete_target.clone()));
                                                    }><Icon icon=IconName::Trash size=17/></button>
                                                </div>
                                            </article>
                                        }
                                    }
                                />
                                <For
                                    each=move || files.files.clone()
                                    key=|file| file.id.clone()
                                    children=move |file| view! { <FileCard file=file request_generation=request_generation reload=reload/> }
                                />
                            </div>
                            {(!files.complete || files.next_cursor.is_some()).then(|| view! {
                                <div class="pagination-note" role="status"><Icon icon=IconName::Clock size=17/><span>"More files are available, but additional pages aren’t supported in this preview yet."</span></div>
                            })}
                        }.into_any()
                    }
                }
            }}

            <Show when=move || create_open.get()>
                <Dialog title="Create a new channel" description="A Telegram channel will be created automatically for this drive folder.".to_owned() on_close=Callback::new(close_dialog)>
                    <form class="dialog-form" on:submit=move |event| { event.prevent_default(); create(()); }>
                        <label for="new-folder-name">"Channel name"</label>
                        <input id="new-folder-name" type="text" maxlength="120" placeholder="e.g. Project notes" required autofocus
                            prop:value=move || folder_name.get()
                            on:input=move |event| folder_name.set(event_target_value(&event))
                        />
                        <ActionError error=action_error/>
                        <div class="dialog-actions">
                            <button class="button button-secondary" type="button" disabled=move || action_pending.get() on:click=move |_| close_dialog(())>"Cancel"</button>
                            <button class="button button-primary" type="submit" disabled=move || action_pending.get()>{move || if action_pending.get() { view! { <Spinner/>"Creating…" }.into_any() } else { view! { <Icon icon=IconName::Plus size=18/>"Create channel" }.into_any() }}</button>
                        </div>
                    </form>
                </Dialog>
            </Show>

            <Show when=move || rename_folder.get().is_some()>
                <Dialog title="Rename channel" description="The channel contents will stay exactly where they are.".to_owned() on_close=Callback::new(close_dialog)>
                    <form class="dialog-form" on:submit=move |event| { event.prevent_default(); rename(()); }>
                        <label for="rename-folder-name">"Channel name"</label>
                        <input id="rename-folder-name" type="text" maxlength="120" required autofocus
                            prop:value=move || folder_name.get()
                            on:input=move |event| folder_name.set(event_target_value(&event))
                        />
                        <ActionError error=action_error/>
                        <div class="dialog-actions">
                            <button class="button button-secondary" type="button" disabled=move || action_pending.get() on:click=move |_| close_dialog(())>"Cancel"</button>
                            <button class="button button-primary" type="submit" disabled=move || action_pending.get()>{move || if action_pending.get() { view! { <Spinner/>"Saving…" }.into_any() } else { view! { <Icon icon=IconName::Check size=18/>"Save changes" }.into_any() }}</button>
                        </div>
                    </form>
                </Dialog>
            </Show>

            <Show when=move || delete_folder.get().is_some()>
                <Dialog title="Delete this channel and all files?" description="This permanently deletes the Telegram channel and every file message in it. This action cannot be undone.".to_owned() on_close=Callback::new(close_dialog)>
                    <div class="delete-confirmation">
                        <span class="state-icon state-icon-error"><Icon icon=IconName::Trash size=23/></span>
                        <p>"You’re about to delete "<strong>{move || delete_folder.get().map(|folder| folder.name).unwrap_or_default()}</strong>"."</p>
                    </div>
                    <ActionError error=action_error/>
                    <div class="dialog-actions">
                        <button class="button button-secondary" type="button" disabled=move || action_pending.get() on:click=move |_| close_dialog(())>"Keep channel"</button>
                        <button class="button button-danger" type="button" disabled=move || action_pending.get() on:click=delete>{move || if action_pending.get() { view! { <Spinner/>"Deleting…" }.into_any() } else { view! { <Icon icon=IconName::Trash size=18/>"Delete channel" }.into_any() }}</button>
                    </div>
                </Dialog>
            </Show>
        </div>
    }
}

async fn load_drive(folder_id: Option<&str>, query: &str) -> Result<DriveData, ApiError> {
    let folders = api::list_folders(folder_id).await?;
    let files = api::list_files(folder_id, Some(query)).await?;
    Ok(DriveData { folders, files })
}

fn current_session(session: SessionState) -> Option<SessionResponse> {
    match session.status.get_untracked() {
        SessionStatus::Authenticated(authenticated) => Some(authenticated),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_mutation_result(
    session: SessionState,
    result: Result<(), ApiError>,
    auth_generation: u64,
    account_id: uuid::Uuid,
    own_request: u64,
    request_generation: RwSignal<u64>,
    action_pending: RwSignal<bool>,
    action_error: RwSignal<Option<String>>,
    reload: RwSignal<u64>,
) -> bool {
    if request_generation.get_untracked() != own_request
        || !session.is_current(auth_generation, account_id)
    {
        return false;
    }
    action_pending.set(false);
    match result {
        Ok(()) => {
            reload.update(|version| *version = version.wrapping_add(1));
            true
        }
        Err(error) if error.is_unauthorized() => {
            session.expire(auth_generation, account_id);
            false
        }
        Err(error) => {
            action_error.set(Some(error.message));
            false
        }
    }
}

#[component]
fn ActionError(error: RwSignal<Option<String>>) -> impl IntoView {
    view! {
        {move || error.get().map(|message| view! {
            <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div>
        })}
    }
}

#[component]
fn FileCard(
    file: DriveFile,
    request_generation: RwSignal<u64>,
    reload: RwSignal<u64>,
) -> impl IntoView {
    let preferences = expect_context::<Preferences>();
    let action_file = file.clone();
    let session = expect_context::<SessionState>();
    let transfer_center = expect_context::<TransferCenterState>();
    let preparing = RwSignal::new(false);
    let delete_open = RwSignal::new(false);
    let deleting = RwSignal::new(false);
    let delete_error = RwSignal::new(Option::<String>::None);
    let download_error = RwSignal::new(Option::<String>::None);
    let file_id = file.id.clone();
    let protected_file_id = file.id.clone();
    let display_name = file.name.clone();
    let download_label = format!("Download {}", file.name);
    let delete_label = format!("Delete {}", file.name);
    let delete_file_id = file.id.clone();
    let mime_type = file.mime_type.clone();
    let protected = file.protected;
    let size = file.size;
    let icon = match file.kind {
        FileKind::Image => IconName::Image,
        FileKind::Video => IconName::Video,
        FileKind::Document => IconName::Document,
        FileKind::Audio | FileKind::Archive | FileKind::Other => IconName::File,
    };
    let icon_class = match file.kind {
        FileKind::Image => "entry-icon file-icon image-icon",
        FileKind::Video => "entry-icon file-icon video-icon",
        FileKind::Audio => "entry-icon file-icon audio-icon",
        FileKind::Archive => "entry-icon file-icon archive-icon",
        FileKind::Document | FileKind::Other => "entry-icon file-icon",
    };
    let modified = file.modified_at.format("%d %b %Y").to_string();

    let start_download = move |_: ()| {
        if preparing.get_untracked() {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        let file_id = file_id.clone();
        preparing.set(true);
        download_error.set(None);
        spawn_local(async move {
            let result = api::prepare_download(&file_id, &authenticated.csrf_token).await;
            if request_generation.get_untracked() != own_request
                || !session.is_current(auth_generation, account_id)
            {
                return;
            }
            preparing.set(false);
            match result {
                Ok(response) => {
                    transfer_center.record_transfer(response.transfer);
                    let navigated = web_sys::window()
                        .map(|window| window.location())
                        .ok_or_else(|| "Browser navigation is unavailable.".to_owned())
                        .and_then(|location| {
                            location
                                .assign(&response.download_url)
                                .map_err(|_| "The browser couldn’t open this download.".to_owned())
                        });
                    if let Err(error) = navigated {
                        download_error.set(Some(error));
                    }
                }
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                }
                Err(error) => download_error.set(Some(error.message)),
            }
        });
    };

    let delete_confirmed = Callback::new(move |_| {
        if deleting.get_untracked() {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        deleting.set(true);
        delete_error.set(None);
        let id = delete_file_id.clone();
        spawn_local(async move {
            let result = api::delete_file(&id, &authenticated.csrf_token).await;
            let applied = handle_mutation_result(
                session,
                result,
                auth_generation,
                account_id,
                own_request,
                request_generation,
                deleting,
                delete_error,
                reload,
            );
            if applied {
                delete_open.set(false);
            }
        });
    });

    view! {
        <article class="entry-card file-card">
            <div class="entry-main">
                <span class=icon_class><Icon icon=icon size=24/></span>
                <span class="entry-copy">
                    <strong>{display_name}</strong>
                    <span>{format_size(size)}<Show when=move || preferences.value.get().show_file_details><span class="detail-separator">"·"</span>{modified.clone()}</Show></span>
                </span>
                {protected.then(|| view! { <span class="protected-badge" title="Protected file: preview and sharing are unavailable"><Icon icon=IconName::Lock size=13/><span>"Protected"</span></span> })}
            </div>
            <div class="file-type-label">{mime_type}</div>
            <div class="entry-actions file-actions">
                <FileActions file=action_file request_generation=request_generation/>
                {if protected {
                    view! { <ProtectedDownloadAction file_id=protected_file_id transfer_id=uuid::Uuid::nil() expected_ciphertext_len=size name=file.name.clone() request_generation=request_generation/> }.into_any()
                } else {
                    view! {
                        <button class="icon-button" type="button" aria-label=download_label title="Download file" disabled=move || preparing.get() on:click=move |_| start_download(())>
                            {move || if preparing.get() { view! { <Spinner size=17/> }.into_any() } else { view! { <Icon icon=IconName::Download size=18/> }.into_any() }}
                        </button>
                    }.into_any()
                }}
                <button class="icon-button danger-hover" type="button" aria-label=delete_label title="Delete file" disabled=move || deleting.get() on:click=move |_| {
                    delete_error.set(None);
                    delete_open.set(true);
                }><Icon icon=IconName::Trash size=18/></button>
            </div>
            {protected.then(|| view! {
                <div class="protected-action-note"><Icon icon=IconName::Lock size=13/><span>"Preview and sharing are unavailable for this protected file."</span></div>
            })}
            {move || download_error.get().map(|message| view! {
                <div class="file-download-error" role="alert"><Icon icon=IconName::Alert size=14/><span>{message}</span></div>
            })}
            <Show when=move || delete_open.get()>
                {let confirm_delete = delete_confirmed; view! {
                <Dialog title="Delete this file?" description="This permanently deletes the Telegram file message. This action cannot be undone.".to_owned() on_close=Callback::new(move |_| {
                    if !deleting.get_untracked() {
                        delete_open.set(false);
                        delete_error.set(None);
                    }
                })>
                    <div class="delete-confirmation">
                        <span class="state-icon state-icon-error"><Icon icon=IconName::Trash size=23/></span>
                        <p>"You’re about to delete this file from Telegram."</p>
                    </div>
                    <ActionError error=delete_error/>
                    <div class="dialog-actions">
                        <button class="button button-secondary" type="button" disabled=move || deleting.get() on:click=move |_| delete_open.set(false)>"Keep file"</button>
                        <button class="button button-danger" type="button" disabled=move || deleting.get() on:click=move |_| confirm_delete.run(())>
                            {move || if deleting.get() { view! { <Spinner/>"Deleting…" }.into_any() } else { view! { <Icon icon=IconName::Trash size=18/>"Delete file" }.into_any() }}
                        </button>
                    </div>
                </Dialog>
                }}
            </Show>
        </article>
    }
}

#[component]
fn DriveSkeleton() -> impl IntoView {
    view! {
        <div class="drive-skeleton" role="status" aria-label="Loading drive contents">
            <span class="sr-only">"Loading your files and folders…"</span>
            {(0..6).map(|_| view! {
                <div class="skeleton-card" aria-hidden="true"><span class="skeleton skeleton-icon"></span><div><span class="skeleton skeleton-title"></span><span class="skeleton skeleton-subtitle"></span></div></div>
            }).collect_view()}
        </div>
    }
}

fn format_count(count: u64, noun: &str) -> String {
    if count == 1 {
        format!("1 {noun}")
    } else {
        format!("{count} {noun}s")
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

fn encode_query(value: &str) -> String {
    let params = web_sys::UrlSearchParams::new().expect("URLSearchParams is available in browsers");
    params.append("q", value);
    params
        .to_string()
        .as_string()
        .unwrap_or_default()
        .strip_prefix("q=")
        .unwrap_or_default()
        .to_owned()
}
