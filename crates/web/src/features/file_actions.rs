use leptos::prelude::*;
use leptos::task::spawn_local;
use salvage_protocol::{DriveFile, SessionResponse, Share};
use uuid::Uuid;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::HtmlInputElement;

use crate::api;
use crate::components::{Dialog, ErrorState, Icon, IconName, Spinner};
use crate::features::transfers::TransferCenterState;
use crate::state::{SessionState, SessionStatus};

const MAX_TEXT_PREVIEW_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PreviewKind {
    Text,
    Image,
    Pdf,
    Audio,
    Video,
    Unsupported,
}

#[derive(Clone)]
struct PreparedPreview {
    kind: PreviewKind,
    inline_url: String,
    download_url: String,
    image_alt: String,
    media_title: String,
    mime_type: String,
    unsupported_reason: String,
}

#[component]
pub fn FileActions(file: DriveFile, request_generation: RwSignal<u64>) -> impl IntoView {
    view! {
        <PreviewAction file=file.clone() request_generation=request_generation/>
        <ShareAction file=file request_generation=request_generation/>
    }
}

#[component]
fn PreviewAction(file: DriveFile, request_generation: RwSignal<u64>) -> impl IntoView {
    let session = expect_context::<SessionState>();
    let transfer_center = expect_context::<TransferCenterState>();
    let protected = file.protected;
    let file_id = file.id.clone();
    let name = file.name.clone();
    let mime_type = file.mime_type.clone();
    let file_size = file.size;
    let kind = preview_kind(&file);
    let open = RwSignal::new(false);
    let preparing = RwSignal::new(false);
    let text_loading = RwSignal::new(false);
    let prepared = RwSignal::new(Option::<PreparedPreview>::None);
    let text = RwSignal::new(Option::<String>::None);
    let error = RwSignal::new(Option::<String>::None);
    let local_generation = RwSignal::new(0_u64);
    let prepared_image_alt = format!("Preview of {name}");
    let prepared_media_title = format!("Inline preview of {name}");
    let prepared_mime_type = mime_type.clone();
    let prepared_unsupported_reason = unsupported_reason(&mime_type, file_size);

    let start_preview: Callback<()> = Callback::new(move |_: ()| {
        if protected {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        local_generation.update(|generation| *generation = generation.wrapping_add(1));
        let own_generation = local_generation.get_untracked();
        open.set(true);
        preparing.set(true);
        text_loading.set(false);
        prepared.set(None);
        text.set(None);
        error.set(None);
        let file_id = file_id.clone();
        let response_image_alt = prepared_image_alt.clone();
        let response_media_title = prepared_media_title.clone();
        let response_mime_type = prepared_mime_type.clone();
        let response_unsupported_reason = prepared_unsupported_reason.clone();

        spawn_local(async move {
            let result = api::prepare_download(&file_id, &authenticated.csrf_token).await;
            if !valid_request(
                session,
                auth_generation,
                account_id,
                request_generation,
                own_request,
                local_generation,
                own_generation,
            ) {
                return;
            }
            preparing.set(false);
            match result {
                Ok(response) => {
                    transfer_center.record_transfer(response.transfer);
                    let inline_url = inline_url(&response.download_url);
                    prepared.set(Some(PreparedPreview {
                        kind,
                        inline_url: inline_url.clone(),
                        download_url: response.download_url,
                        image_alt: response_image_alt,
                        media_title: response_media_title,
                        mime_type: response_mime_type,
                        unsupported_reason: response_unsupported_reason,
                    }));
                    if kind == PreviewKind::Text {
                        text_loading.set(true);
                        spawn_local(async move {
                            let result = api::get_inline_text(&inline_url).await;
                            if !valid_request(
                                session,
                                auth_generation,
                                account_id,
                                request_generation,
                                own_request,
                                local_generation,
                                own_generation,
                            ) {
                                return;
                            }
                            text_loading.set(false);
                            match result {
                                Ok(contents) => text.set(Some(contents)),
                                Err(error) if error.is_unauthorized() => {
                                    session.expire(auth_generation, account_id);
                                }
                                Err(api_error) => error.set(Some(api_error.message)),
                            }
                        });
                    }
                }
                Err(api_error) if api_error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                }
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    });

    let close_preview: Callback<()> = Callback::new(move |_: ()| {
        local_generation.update(|generation| *generation = generation.wrapping_add(1));
        open.set(false);
        preparing.set(false);
        text_loading.set(false);
        prepared.set(None);
        text.set(None);
        error.set(None);
    });

    let preview_label = format!("Preview {name}");
    let preview_title = format!("Preview {name}");
    let dialog_description = format!("{mime_type} · Inline preview");

    view! {
        <button
            class="icon-button"
            type="button"
            aria-label=preview_label
            title=if protected { "Preview unavailable for protected files" } else { "Preview file" }
            disabled=protected
            on:click=move |_| start_preview.run(())
        >
            <Icon icon=IconName::Eye size=18/>
        </button>
        <Show when=move || open.get()>
            <Dialog title=preview_title.clone() description=dialog_description.clone() on_close=close_preview>
                <div class="preview-content">
                    {move || {
                        if let Some(message) = error.get() {
                            view! {
                                <ErrorState title="Preview couldn’t be loaded" message=message on_retry=start_preview/>
                            }.into_any()
                        } else if preparing.get() {
                            view! { <PreviewLoading message="Preparing a secure inline preview…"/> }.into_any()
                        } else if let Some(preview) = prepared.get() {
                            let stage = match preview.kind {
                                PreviewKind::Text => {
                                    if text_loading.get() {
                                        view! { <PreviewLoading message="Reading the text preview…"/> }.into_any()
                                    } else {
                                        view! {
                                            <pre class="text-preview" tabindex="0">{move || text.get().unwrap_or_default()}</pre>
                                        }.into_any()
                                    }
                                }
                                PreviewKind::Image => view! {
                                    <div class="media-preview image-preview"><img src=preview.inline_url.clone() alt=preview.image_alt.clone() on:error=move |_| error.set(Some("The image couldn’t be loaded. Download the file to try another viewer.".to_owned()))/></div>
                                }.into_any(),
                                PreviewKind::Pdf => view! {
                                    <iframe class="pdf-preview" src=preview.inline_url.clone() title=preview.media_title.clone() on:error=move |_| error.set(Some("The PDF preview couldn’t be loaded. Download the file to open it in another viewer.".to_owned()))></iframe>
                                }.into_any(),
                                PreviewKind::Audio => view! {
                                    <div class="media-preview audio-preview"><Icon icon=IconName::File size=30/><audio controls preload="metadata" src=preview.inline_url.clone() on:error=move |_| error.set(Some("The audio couldn’t be loaded. Download the file to try another player.".to_owned()))>"Your browser does not support audio playback."</audio></div>
                                }.into_any(),
                                PreviewKind::Video => view! {
                                    <div class="media-preview video-preview"><video controls playsinline preload="metadata" src=preview.inline_url.clone() on:error=move |_| error.set(Some("The video couldn’t be loaded. Download the file to try another player.".to_owned()))>"Your browser does not support video playback."</video></div>
                                }.into_any(),
                                PreviewKind::Unsupported => view! {
                                    <div class="unsupported-preview">
                                        <span class="state-icon"><Icon icon=IconName::File size=25/></span>
                                        <h3>"No inline preview for this file"</h3>
                                        <p>{preview.unsupported_reason.clone()}</p>
                                    </div>
                                }.into_any(),
                            };
                            view! {
                                {stage}
                                <div class="preview-footer">
                                    <span>{preview.mime_type.clone()}</span>
                                    <a class="button button-secondary button-small" href=preview.download_url.clone()><Icon icon=IconName::Download size=16/>"Download file"</a>
                                </div>
                            }.into_any()
                        } else {
                            view! { <PreviewLoading message="Loading preview…"/> }.into_any()
                        }
                    }}
                </div>
            </Dialog>
        </Show>
    }
}

#[component]
fn PreviewLoading(message: &'static str) -> impl IntoView {
    view! {
        <div class="preview-loading" role="status"><Spinner size=25/><p>{message}</p></div>
    }
}

#[derive(Clone, Copy)]
struct ShareDialogState {
    open: RwSignal<bool>,
    loading: RwSignal<bool>,
    creating: RwSignal<bool>,
    expiry: RwSignal<u16>,
    shares: RwSignal<Vec<Share>>,
    list_error: RwSignal<Option<String>>,
    action_error: RwSignal<Option<String>>,
    created_link: RwSignal<Option<String>>,
    copy_status: RwSignal<Option<String>>,
    revoking: RwSignal<Option<Uuid>>,
    generation: RwSignal<u64>,
}

impl ShareDialogState {
    fn new() -> Self {
        Self {
            open: RwSignal::new(false),
            loading: RwSignal::new(false),
            creating: RwSignal::new(false),
            expiry: RwSignal::new(24),
            shares: RwSignal::new(Vec::new()),
            list_error: RwSignal::new(None),
            action_error: RwSignal::new(None),
            created_link: RwSignal::new(None),
            copy_status: RwSignal::new(None),
            revoking: RwSignal::new(None),
            generation: RwSignal::new(0),
        }
    }
}

#[component]
fn ShareAction(file: DriveFile, request_generation: RwSignal<u64>) -> impl IntoView {
    let session = expect_context::<SessionState>();
    let protected = file.protected;
    let file_id = file.id.clone();
    let name = file.name.clone();
    let state = ShareDialogState::new();
    let open_file_id = file_id.clone();
    let refresh_file_id = file_id.clone();
    let create_file_id = file_id.clone();

    let open_share: Callback<()> = Callback::new(move |_: ()| {
        if protected {
            return;
        }
        state
            .generation
            .update(|generation| *generation = generation.wrapping_add(1));
        state.open.set(true);
        state.shares.set(Vec::new());
        state.list_error.set(None);
        state.action_error.set(None);
        state.created_link.set(None);
        state.copy_status.set(None);
        state.revoking.set(None);
        load_shares(session, request_generation, state, open_file_id.clone());
    });

    let refresh_shares: Callback<()> = Callback::new(move |_: ()| {
        state
            .generation
            .update(|generation| *generation = generation.wrapping_add(1));
        load_shares(session, request_generation, state, refresh_file_id.clone());
    });

    let close_share: Callback<()> = Callback::new(move |_: ()| {
        state
            .generation
            .update(|generation| *generation = generation.wrapping_add(1));
        state.open.set(false);
        state.loading.set(false);
        state.creating.set(false);
        state.created_link.set(None);
        state.copy_status.set(None);
        state.shares.set(Vec::new());
        state.action_error.set(None);
    });

    let create_share: Callback<()> = Callback::new(move |_: ()| {
        if state.creating.get_untracked() || state.loading.get_untracked() {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        let own_generation = state.generation.get_untracked();
        let expiry = state.expiry.get_untracked();
        let file_id = create_file_id.clone();
        state.creating.set(true);
        state.action_error.set(None);
        state.copy_status.set(None);
        spawn_local(async move {
            let result = api::create_share(&file_id, expiry, &authenticated.csrf_token).await;
            if !valid_request(
                session,
                auth_generation,
                account_id,
                request_generation,
                own_request,
                state.generation,
                own_generation,
            ) {
                return;
            }
            state.creating.set(false);
            match result {
                Ok(created) => {
                    state
                        .generation
                        .update(|generation| *generation = generation.wrapping_add(1));
                    let origin = web_sys::window()
                        .and_then(|window| window.location().origin().ok())
                        .unwrap_or_default();
                    state
                        .created_link
                        .set(Some(format!("{origin}{}", created.url_path)));
                    state
                        .shares
                        .update(|shares| shares.insert(0, created.share));
                    state.copy_status.set(Some(
                        "Copy this link now. It cannot be recovered from the metadata list later."
                            .to_owned(),
                    ));
                }
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                }
                Err(error) => state.action_error.set(Some(error.message)),
            }
        });
    });

    let copy_link: Callback<()> = Callback::new(move |_: ()| {
        let Some(link) = state.created_link.get_untracked() else {
            return;
        };
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        let own_generation = state.generation.get_untracked();
        state.copy_status.set(None);
        let clipboard = web_sys::window().and_then(|window| {
            let navigator = window.navigator();
            js_sys::Reflect::get(navigator.as_ref(), &JsValue::from_str("clipboard"))
                .ok()
                .filter(|value| !value.is_null() && !value.is_undefined())
                .map(|value| value.unchecked_into::<web_sys::Clipboard>())
        });
        let Some(clipboard) = clipboard else {
            state.copy_status.set(Some(
                "Clipboard access is unavailable. Select the link field and copy it manually."
                    .to_owned(),
            ));
            return;
        };
        spawn_local(async move {
            let result = JsFuture::from(clipboard.write_text(&link)).await;
            if !valid_request(
                session,
                auth_generation,
                account_id,
                request_generation,
                own_request,
                state.generation,
                own_generation,
            ) {
                return;
            }
            match result {
                Ok(_) => state.copy_status.set(Some("Link copied.".to_owned())),
                Err(_) => state.copy_status.set(Some(
                    "Clipboard access was denied. Select the link field and copy it manually."
                        .to_owned(),
                )),
            }
        });
    });

    let revoke_share: Callback<Uuid> = Callback::new(move |share_id: Uuid| {
        if state.revoking.get_untracked().is_some() {
            return;
        }
        let Some(authenticated) = current_session(session) else {
            return;
        };
        let auth_generation = session.generation.get_untracked();
        let account_id = authenticated.account.id;
        let own_request = request_generation.get_untracked();
        let own_generation = state.generation.get_untracked();
        state.revoking.set(Some(share_id));
        state.action_error.set(None);
        spawn_local(async move {
            let result = api::revoke_share(share_id, &authenticated.csrf_token).await;
            if !valid_request(
                session,
                auth_generation,
                account_id,
                request_generation,
                own_request,
                state.generation,
                own_generation,
            ) {
                return;
            }
            state.revoking.set(None);
            match result {
                Ok(revoked) => state.shares.update(|shares| {
                    if let Some(share) = shares.iter_mut().find(|share| share.id == share_id) {
                        *share = revoked;
                    }
                }),
                Err(error) if error.is_unauthorized() => {
                    session.expire(auth_generation, account_id);
                }
                Err(error) => state.action_error.set(Some(error.message)),
            }
        });
    });

    let share_label = format!("Share {name}");
    let share_title = format!("Share {name}");

    view! {
        <button
            class="icon-button"
            type="button"
            aria-label=share_label
            title=if protected { "Sharing unavailable for protected files" } else { "Create a public share link" }
            disabled=protected
            on:click=move |_| open_share.run(())
        >
            <Icon icon=IconName::Share size=18/>
        </button>
        <Show when=move || state.open.get()>
            <Dialog title=share_title.clone() description="Create a plain-file public link or manage existing share metadata.".to_owned() on_close=close_share>
                <div class="share-content">
                    <div class="share-warning" role="note">
                        <Icon icon=IconName::Alert size=18/>
                        <p>"Anyone with the link can read this file until the link expires or is revoked."</p>
                    </div>

                    <form class="share-create-form" on:submit=move |event| { event.prevent_default(); create_share.run(()); }>
                        <label for="share-expiry">"Link expires after"</label>
                        <div class="share-create-row">
                            <select id="share-expiry" on:change=move |event| {
                                let hours = event_target_value(&event).parse::<u16>().unwrap_or(24);
                                state.expiry.set(hours);
                            }>
                                <option value="0" selected=move || state.expiry.get() == 0>"Never expires"</option>
                                <option value="1" selected=move || state.expiry.get() == 1>"1 hour"</option>
                                <option value="24" selected=move || state.expiry.get() == 24>"24 hours"</option>
                                <option value="72" selected=move || state.expiry.get() == 72>"3 days"</option>
                                <option value="168" selected=move || state.expiry.get() == 168>"7 days"</option>
                            </select>
                            <button class="button button-primary" type="submit" disabled=move || state.creating.get() || state.loading.get()>
                                {move || if state.creating.get() { view! { <Spinner/>"Creating…" }.into_any() } else { view! { <Icon icon=IconName::Share size=17/>"Create share link" }.into_any() }}
                            </button>
                        </div>
                    </form>

                    {move || state.action_error.get().map(|message| view! {
                        <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div>
                    })}

                    {move || state.created_link.get().map(|link| view! {
                        <section class="created-share-link" aria-labelledby="created-link-heading">
                            <div class="created-link-heading"><span class="state-icon"><Icon icon=IconName::Check size=20/></span><div><h3 id="created-link-heading">"Your share link is ready"</h3><p>"This full link is shown only once."</p></div></div>
                            <label for="created-share-url">"Share link"</label>
                            <div class="share-link-input-row">
                                <input id="created-share-url" type="text" readonly prop:value=link.clone() on:focus=move |event| {
                                    if let Some(input) = event.target().and_then(|target| target.dyn_into::<HtmlInputElement>().ok()) {
                                        input.select();
                                    }
                                }/>
                                <button class="button button-secondary" type="button" on:click=move |_| copy_link.run(())><Icon icon=IconName::Copy size=17/>"Copy share link"</button>
                            </div>
                            {move || state.copy_status.get().map(|status| view! { <p class="copy-status" role="status">{status}</p> })}
                        </section>
                    })}

                    <section class="existing-shares" aria-labelledby="existing-shares-heading">
                        <div class="existing-shares-heading"><h3 id="existing-shares-heading">"Existing share metadata"</h3><span>{move || format!("{}", state.shares.get().len())}</span></div>
                        <p class="share-metadata-explanation">"Existing entries contain dates and status only. Their full links and tokens cannot be recovered."</p>
                        {move || {
                            if state.loading.get() {
                                view! { <PreviewLoading message="Loading share metadata…"/> }.into_any()
                            } else if let Some(message) = state.list_error.get() {
                                view! { <ErrorState title="Shares couldn’t be loaded" message=message on_retry=refresh_shares/> }.into_any()
                            } else if state.shares.get().is_empty() {
                                view! { <p class="shares-empty">"No share links have been created for this file."</p> }.into_any()
                            } else {
                                view! {
                                    <div class="share-list" role="list">
                                        <For
                                            each=move || state.shares.get()
                                            key=|share| (share.id, share.revoked_at.map(|date| date.timestamp_millis()))
                                            children=move |share| view! {
                                                <ShareMetadataRow share=share on_revoke=revoke_share revoking=state.revoking/>
                                            }
                                        />
                                    </div>
                                }.into_any()
                            }
                        }}
                    </section>
                </div>
            </Dialog>
        </Show>
    }
}

#[component]
fn ShareMetadataRow(
    share: Share,
    on_revoke: Callback<Uuid>,
    revoking: RwSignal<Option<Uuid>>,
) -> impl IntoView {
    let share_id = share.id;
    let expired = share
        .expires_at
        .is_some_and(|expiry| expiry.timestamp_millis() <= js_sys::Date::now() as i64);
    let revoked = share.revoked_at.is_some();
    let status = if revoked {
        "Revoked"
    } else if expired {
        "Expired"
    } else {
        "Active"
    };
    let status_class = if revoked || expired {
        "share-status is-inactive"
    } else {
        "share-status is-active"
    };
    let revoke_label = format!("Revoke share {share_id}");
    let created = share.created_at.format("%d %b %Y %H:%M UTC").to_string();
    let expires = share
        .expires_at
        .map(|expiry| expiry.format("%d %b %Y %H:%M UTC").to_string())
        .unwrap_or_else(|| "Never".to_owned());

    view! {
        <article class="share-metadata-row" role="listitem">
            <div class="share-metadata-main">
                <div><strong>{format!("Share {share_id}")}</strong><span class=status_class>{status}</span></div>
                <p>"Created "{created}</p>
                <p>"Expires "{expires}</p>
            </div>
            <Show when=move || !revoked>
                <button class="button button-secondary button-small" type="button" aria-label=revoke_label.clone() disabled=move || revoking.get() == Some(share_id) on:click=move |_| on_revoke.run(share_id)>
                    {move || if revoking.get() == Some(share_id) { view! { <Spinner size=15/>"Revoking…" }.into_any() } else { view! { "Revoke" }.into_any() }}
                </button>
            </Show>
        </article>
    }
}

fn load_shares(
    session: SessionState,
    request_generation: RwSignal<u64>,
    state: ShareDialogState,
    file_id: String,
) {
    let Some(authenticated) = current_session(session) else {
        return;
    };
    let auth_generation = session.generation.get_untracked();
    let account_id = authenticated.account.id;
    let own_request = request_generation.get_untracked();
    let own_generation = state.generation.get_untracked();
    state.loading.set(true);
    state.list_error.set(None);
    spawn_local(async move {
        let result = api::list_shares(&file_id).await;
        if !valid_request(
            session,
            auth_generation,
            account_id,
            request_generation,
            own_request,
            state.generation,
            own_generation,
        ) {
            return;
        }
        state.loading.set(false);
        match result {
            Ok(shares) => state.shares.set(shares),
            Err(error) if error.is_unauthorized() => {
                session.expire(auth_generation, account_id);
            }
            Err(error) => state.list_error.set(Some(error.message)),
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn valid_request(
    session: SessionState,
    auth_generation: u64,
    account_id: Uuid,
    request_generation: RwSignal<u64>,
    own_request: u64,
    local_generation: RwSignal<u64>,
    own_generation: u64,
) -> bool {
    session.is_current(auth_generation, account_id)
        && request_generation.get_untracked() == own_request
        && local_generation.get_untracked() == own_generation
}

fn current_session(session: SessionState) -> Option<SessionResponse> {
    match session.status.get_untracked() {
        SessionStatus::Authenticated(authenticated) => Some(authenticated),
        _ => None,
    }
}

fn preview_kind(file: &DriveFile) -> PreviewKind {
    let mime_type = file.mime_type.as_str();
    match mime_type {
        "text/plain" if file.size <= MAX_TEXT_PREVIEW_BYTES => PreviewKind::Text,
        "image/png" | "image/jpeg" | "image/gif" | "image/webp" => PreviewKind::Image,
        "application/pdf" => PreviewKind::Pdf,
        value if value.starts_with("audio/") => PreviewKind::Audio,
        value if value.starts_with("video/") => PreviewKind::Video,
        _ => PreviewKind::Unsupported,
    }
}

fn unsupported_reason(mime_type: &str, size: u64) -> String {
    if mime_type == "text/plain" && size > MAX_TEXT_PREVIEW_BYTES {
        "Text previews are limited to 1 MiB. Download this file to read it.".to_owned()
    } else if mime_type == "image/svg+xml" || mime_type == "text/html" {
        "HTML and SVG are not rendered in the previewer. Download the file to open it separately."
            .to_owned()
    } else {
        format!(
            "“{mime_type}” is not supported for inline preview. Download the file to open it in another application."
        )
    }
}

fn inline_url(download_url: &str) -> String {
    if download_url.contains('?') {
        format!("{download_url}&inline=1")
    } else {
        format!("{download_url}?inline=1")
    }
}
