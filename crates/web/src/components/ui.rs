use leptos::html;
use leptos::prelude::*;

use super::{Icon, IconName};

#[component]
pub fn BrandMark(#[prop(default = 42)] size: u16) -> impl IntoView {
    view! {
        <svg class="brand-mark" width=size height=size viewBox="0 0 48 48" fill="none" aria-hidden="true">
            <rect width="48" height="48" rx="14" fill="currentColor"/>
            <path d="M14 32h21a7.5 7.5 0 0 0 1.2-14.9A11.2 11.2 0 0 0 15.1 13 9 9 0 0 0 14 32Z" stroke="white" stroke-width="2.6" stroke-linecap="round"/>
            <path d="m18.5 24.5 5.2 5.2 8-10" stroke="#D9F99D" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
    }
}

#[component]
pub fn Brand(#[prop(default = false)] compact: bool) -> impl IntoView {
    view! {
        <a href="/" class="brand" aria-label="Salvage Cloud home">
            <BrandMark/>
            <span class=move || if compact { "brand-copy is-compact" } else { "brand-copy" }>
                <strong>"salvage"</strong>
                <span>"cloud"</span>
            </span>
        </a>
    }
}

#[component]
pub fn Spinner(#[prop(default = 20)] size: u16) -> impl IntoView {
    view! {
        <svg class="spinner" width=size height=size viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-opacity=".2" stroke-width="2.5"/>
            <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/>
        </svg>
    }
}

#[component]
pub fn LoadingScreen(#[prop(into)] message: String) -> impl IntoView {
    view! {
        <main id="main-content" class="loading-screen">
            <div class="loading-brand"><BrandMark size=52/><span>"salvage cloud"</span></div>
            <div class="loading-indicator" role="status">
                <Spinner size=24/>
                <p>{message}</p>
            </div>
            <span class="loading-footnote">"Your files, within reach."</span>
        </main>
    }
}

#[component]
pub fn ErrorState(
    #[prop(into)] title: String,
    #[prop(into)] message: String,
    #[prop(optional)] on_retry: Option<Callback<()>>,
) -> impl IntoView {
    view! {
        <div class="state-card error-state" role="alert">
            <span class="state-icon state-icon-error"><Icon icon=IconName::Alert size=26/></span>
            <h2>{title}</h2>
            <p>{message}</p>
            {on_retry.map(|retry| view! {
                <button class="button button-secondary" type="button" on:click=move |_| retry.run(())>
                    "Try again"
                </button>
            })}
        </div>
    }
}

#[component]
pub fn EmptyState(
    #[prop(into)] title: String,
    #[prop(into)] message: String,
    #[prop(optional)] action_label: Option<String>,
    #[prop(optional)] on_action: Option<Callback<()>>,
) -> impl IntoView {
    view! {
        <div class="state-card empty-state">
            <span class="empty-illustration" aria-hidden="true">
                <span class="empty-cloud"><Icon icon=IconName::Cloud size=38/></span>
                <span class="empty-folder"><Icon icon=IconName::Folder size=48/></span>
            </span>
            <h2>{title}</h2>
            <p>{message}</p>
            {match (action_label, on_action) {
                (Some(label), Some(action)) => Some(view! {
                    <button class="button button-primary" type="button" on:click=move |_| action.run(())>
                        <Icon icon=IconName::Plus size=18/>
                        {label}
                    </button>
                }),
                _ => None,
            }}
        </div>
    }
}

#[component]
pub fn Dialog(
    #[prop(into)] title: String,
    #[prop(optional, into)] description: Option<String>,
    on_close: Callback<()>,
    children: Children,
) -> impl IntoView {
    let dialog_ref = NodeRef::<html::Dialog>::new();
    let title_id = format!("dialog-title-{}", uuid::Uuid::new_v4().simple());
    let description_id = format!("dialog-description-{}", uuid::Uuid::new_v4().simple());
    let described_by = description.as_ref().map(|_| description_id.clone());

    Effect::new(move |_| {
        if let Some(dialog) = dialog_ref.get() {
            let _ = dialog.show_modal();
        }
    });

    view! {
        <dialog
            node_ref=dialog_ref
            class="dialog"
            aria-labelledby=title_id
            aria-describedby=described_by
            on:cancel=move |event: web_sys::Event| {
                event.prevent_default();
                on_close.run(());
            }
        >
            <div class="dialog-header">
                <div>
                    <h2 id=title_id.clone()>{title}</h2>
                    {description.map(|description| view! { <p id=description_id>{description}</p> })}
                </div>
                <button class="icon-button" type="button" aria-label="Close dialog" on:click=move |_| on_close.run(())>
                    <Icon icon=IconName::Close/>
                </button>
            </div>
            <div class="dialog-body">{children()}</div>
        </dialog>
    }
}
