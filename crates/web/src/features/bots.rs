use leptos::prelude::*;
use leptos::task::spawn_local;
use salvage_protocol::BotTokenInfo;
use uuid::Uuid;

use crate::api;
use crate::components::{Icon, IconName, Spinner};
use crate::state::{SessionState, SessionStatus};

#[component]
pub fn BotSettings() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let bots = RwSignal::new(Vec::<BotTokenInfo>::new());
    let label = RwSignal::new(String::new());
    let token = RwSignal::new(String::new());
    let busy = RwSignal::new(false);
    let error = RwSignal::new(Option::<String>::None);
    let notice = RwSignal::new(Option::<String>::None);
    let refresh = RwSignal::new(0_u64);

    Effect::new(move |_| {
        let _ = refresh.get();
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
        });
    });

    let add = move |_| {
        let Some(authenticated) = session.authenticated_session() else {
            return;
        };
        if busy.get_untracked() {
            return;
        }
        let label_value = label.get_untracked().trim().to_owned();
        let token_value = token.get_untracked().trim().to_owned();
        if label_value.is_empty() || token_value.is_empty() {
            error.set(Some("Enter a bot label and token.".to_string()));
            return;
        }
        busy.set(true);
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = api::add_bot(&label_value, &token_value, &authenticated.csrf_token).await;
            busy.set(false);
            match result {
                Ok(bot) => {
                    token.set(String::new());
                    label.set(String::new());
                    bots.update(|items| items.insert(0, bot));
                    notice.set(Some(
                        "Bot connected. Its token remains encrypted on the server.".to_string(),
                    ));
                }
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    };

    let remove = move |id: Uuid| {
        let Some(authenticated) = session.authenticated_session() else {
            return;
        };
        busy.set(true);
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = api::delete_bot(id, &authenticated.csrf_token).await;
            busy.set(false);
            match result {
                Ok(()) => {
                    bots.update(|items| items.retain(|bot| bot.id != id));
                    notice.set(Some("Bot removed from Salvage Cloud. Revoke the token in BotFather if it is no longer needed.".to_string()));
                }
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    };

    let provision = move |id: Uuid| {
        let Some(authenticated) = session.authenticated_session() else {
            return;
        };
        busy.set(true);
        error.set(None);
        notice.set(None);
        spawn_local(async move {
            let result = api::provision_bot(id, &authenticated.csrf_token).await;
            busy.set(false);
            match result {
                Ok(()) => notice.set(Some(
                    "Bot access synchronized across current channels.".to_string(),
                )),
                Err(api_error) => error.set(Some(api_error.message)),
            }
        });
    };

    view! {
        <section class="settings-card" aria-labelledby="bots-heading">
            <div class="settings-card-heading">
                <span class="settings-card-icon"><Icon icon=IconName::Cloud size=21/></span>
                <div><h3 id="bots-heading">"Channel upload bots"</h3><p>"Use your own bots to publish into channels or groups they administer. Saved Messages always stays with your personal account."</p></div>
            </div>
            <div class="vault-primary-controls bot-settings-form">
                <div class="bot-field">
                    <label for="bot-label">"Bot label"</label>
                    <input id="bot-label" type="text" maxlength="80" autocomplete="off" prop:value=move || label.get() on:input=move |event| label.set(event_target_value(&event))/>
                </div>
                <div class="bot-field">
                    <label for="bot-token">"Bot token"</label>
                    <input id="bot-token" type="password" autocomplete="off" prop:value=move || token.get() on:input=move |event| token.set(event_target_value(&event))/>
                </div>
                <button class="button button-primary" type="button" disabled=move || busy.get() on:click=add>
                    {move || if busy.get() { view! { <Spinner/> }.into_any() } else { view! { <Icon icon=IconName::Plus size=17/> }.into_any() }}
                    "Add bot"
                </button>
            </div>
            <p class="field-help">"Tokens and MTProto sessions are encrypted on the backend. Bots publish one at a time and are never used to bypass Telegram limits."</p>
            {move || error.get().map(|message| view! { <div class="form-error" role="alert"><Icon icon=IconName::Alert size=17/><span>{message}</span></div> })}
            {move || notice.get().map(|message| view! { <div class="inline-notice vault-notice" role="status"><Icon icon=IconName::Check size=17/><span>{message}</span></div> })}
            <div class="bot-token-list">
                <For each=move || bots.get() key=|bot| bot.id children=move |bot| {
                    let name = bot.bot_username.clone().map(|username| format!("@{username}")).unwrap_or_else(|| format!("bot {}", bot.bot_user_id));
                    view! {
                        <div class="bot-token-row">
                            <div><strong>{bot.label.clone()}</strong><span>{name}</span></div>
                            <div class="bot-token-actions">
                                <button class="button button-secondary button-small" type="button" disabled=move || busy.get() on:click=move |_| provision(bot.id)>"Sync access"</button>
                                <button class="button button-secondary button-small" type="button" disabled=move || busy.get() on:click=move |_| remove(bot.id)>"Remove"</button>
                            </div>
                        </div>
                    }
                }/>
            </div>
        </section>
    }
}
