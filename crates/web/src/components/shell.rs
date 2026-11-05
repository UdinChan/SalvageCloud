use leptos::prelude::*;
use leptos_router::components::A;
use leptos_router::hooks::{use_location, use_navigate};

use crate::components::{Brand, BrandMark, ErrorState, Icon, IconName, LoadingScreen};
use crate::state::{SessionState, SessionStatus};

#[component]
pub fn Protected(children: ChildrenFn) -> impl IntoView {
    let session = expect_context::<SessionState>();
    let children = StoredValue::new(children);

    view! {
        {move || {
            if matches!(session.status.get(), SessionStatus::Authenticated(_)) {
                children
                    .with_value(|children| view! { <AppShell children=children.clone()/> })
                    .into_any()
            } else {
                view! { <AuthFallback/> }.into_any()
            }
        }}
    }
}

#[component]
fn AuthFallback() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let navigate = use_navigate();

    Effect::new(move |_| {
        if matches!(session.status.get(), SessionStatus::Anonymous) {
            navigate("/login", Default::default());
        }
    });

    view! {
        {move || match session.status.get() {
            SessionStatus::Error(message) => view! {
                <main id="main-content" class="standalone-page">
                    <div class="standalone-brand"><Brand/></div>
                    <ErrorState
                        title="We couldn’t restore your session"
                        message=message
                        on_retry=Callback::new(move |_| session.restore_session())
                    />
                </main>
            }.into_any(),
            _ => view! { <LoadingScreen message="Restoring your secure session"/> }.into_any(),
        }}
    }
}

#[component]
pub fn AppShell(children: ChildrenFn) -> impl IntoView {
    let session = expect_context::<SessionState>();
    let location = use_location();
    let mobile_open = RwSignal::new(false);
    let pathname = move || location.pathname.get();

    Effect::new(move |_| {
        let _ = location.pathname.get();
        mobile_open.set(false);
    });

    let page_title = move || {
        let path = pathname();
        if path.starts_with("/settings") {
            "Settings"
        } else if path.starts_with("/transfers") {
            "Transfer center"
        } else {
            "My drive"
        }
    };

    let account_initial = move || {
        session
            .account()
            .and_then(|account| account.display_name.chars().next())
            .map(|initial| initial.to_uppercase().collect::<String>())
            .unwrap_or_else(|| "S".to_owned())
    };
    let account_name = move || {
        session
            .account()
            .map(|account| account.display_name)
            .unwrap_or_else(|| "Salvage account".to_owned())
    };

    view! {
        <div class="app-shell">
            <button
                class=move || if mobile_open.get() { "sidebar-backdrop is-visible" } else { "sidebar-backdrop" }
                type="button"
                aria-label="Close navigation"
                tabindex=move || if mobile_open.get() { "0" } else { "-1" }
                on:click=move |_| mobile_open.set(false)
            ></button>

            <aside id="app-sidebar" class=move || if mobile_open.get() { "sidebar is-open" } else { "sidebar" } aria-label="Primary navigation">
                <div class="sidebar-header">
                    <Brand/>
                    <button class="icon-button sidebar-close" type="button" aria-label="Close navigation" on:click=move |_| mobile_open.set(false)>
                        <Icon icon=IconName::Close/>
                    </button>
                </div>

                <nav class="sidebar-nav">
                    <span class="nav-section-label">"Workspace"</span>
                    <A href="/drive" attr:class=move || if pathname().starts_with("/drive") { "nav-link is-active" } else { "nav-link" }>
                        <Icon icon=IconName::Folder/>
                        <span>"My drive"</span>
                    </A>
                    <A href="/transfers" attr:class=move || if pathname().starts_with("/transfers") { "nav-link is-active" } else { "nav-link" }>
                        <Icon icon=IconName::Transfer/>
                        <span>"Transfer center"</span>
                    </A>
                    <span class="nav-section-label nav-section-spaced">"Account"</span>
                    <A href="/settings" attr:class=move || if pathname().starts_with("/settings") { "nav-link is-active" } else { "nav-link" }>
                        <Icon icon=IconName::Settings/>
                        <span>"Settings"</span>
                    </A>
                </nav>

                <div class="sidebar-bottom">
                    <div class="privacy-note">
                        <span class="privacy-icon"><Icon icon=IconName::Shield size=19/></span>
                        <div><strong>"Session protected"</strong><span>"Credentials stay out of browser storage."</span></div>
                    </div>
                    <div class="account-row">
                        <span class="avatar" aria-hidden="true">{account_initial}</span>
                        <div class="account-copy"><strong>{account_name}</strong><span>"Connected account"</span></div>
                        <button class="icon-button" type="button" title="Sign out" aria-label="Sign out" on:click=move |_| session.logout()>
                            <Icon icon=IconName::Logout size=19/>
                        </button>
                    </div>
                </div>
            </aside>

            <div class="app-frame">
                <header class="topbar">
                    <div class="topbar-title">
                        <button class="icon-button mobile-menu" type="button" aria-label="Open navigation" aria-controls="app-sidebar" aria-expanded=move || mobile_open.get().to_string() on:click=move |_| mobile_open.set(true)>
                            <Icon icon=IconName::Menu size=22/>
                        </button>
                        <span class="topbar-mobile-logo"><BrandMark size=32/></span>
                        <h1>{page_title}</h1>
                    </div>
                    <div class="topbar-account">
                        <span class="status-dot" aria-hidden="true"></span>
                        <span>{account_name}</span>
                    </div>
                </header>
                <main id="main-content" class="main-content" tabindex="-1">
                    {children()}
                </main>
            </div>
        </div>
    }
}
