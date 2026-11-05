mod api;
mod components;
mod encryption;
mod features;
mod state;
mod transfer_store;

use leptos::prelude::*;
use leptos_router::components::{Route, Router, Routes};
use leptos_router::path;

use crate::components::LoadingScreen;
use crate::encryption::EncryptionContext;
use crate::features::{DrivePage, LoginPage, SettingsPage, TransferCenterState, TransfersPage};
use crate::state::{Preferences, SessionState, SessionStatus};

#[component]
pub fn App() -> impl IntoView {
    let session = SessionState::new();
    let preferences = Preferences::new();
    let transfer_center = TransferCenterState::new();
    let encryption = EncryptionContext::new();
    provide_context(session);
    provide_context(preferences);
    provide_context(transfer_center);
    provide_context(encryption);

    Effect::new(move |_| {
        encryption.initialize();
    });

    Effect::new(move |_| {
        session.restore_session();
    });

    let observed_session_generation = RwSignal::new(None::<u64>);
    Effect::new(move |_| {
        let generation = session.generation.get();
        let account_id = session.account().map(|account| account.id);
        encryption.synchronize(account_id, generation);
        if observed_session_generation
            .get_untracked()
            .is_some_and(|observed| observed != generation)
        {
            transfer_center.reset();
        }
        observed_session_generation.set(Some(generation));
    });

    Effect::new(move |_| {
        let preferences = preferences.value.get();
        if let Some(document) = web_sys::window().and_then(|window| window.document())
            && let Some(root) = document.document_element()
        {
            let _ = root.set_attribute("data-theme", preferences.theme.as_str());
            let _ = root.set_attribute("data-density", preferences.density.as_str());
        }
    });

    view! {
        <Router>
            <a class="skip-link" href="#main-content">"Skip to main content"</a>
            <Routes fallback=|| view! { <NotFoundPage/> }>
                <Route path=path!("/") view=HomePage/>
                <Route path=path!("/login") view=LoginPage/>
                <Route path=path!("/drive") view=DrivePage/>
                <Route path=path!("/drive/folder/:id") view=DrivePage/>
                <Route path=path!("/transfers") view=TransfersPage/>
                <Route path=path!("/settings") view=SettingsPage/>
            </Routes>
        </Router>
    }
}

#[component]
fn HomePage() -> impl IntoView {
    let session = expect_context::<SessionState>();
    let navigate = leptos_router::hooks::use_navigate();

    Effect::new(move |_| match session.status.get() {
        SessionStatus::Loading => {}
        SessionStatus::Anonymous => navigate("/login", Default::default()),
        SessionStatus::Authenticated(_) => navigate("/drive", Default::default()),
        SessionStatus::Error(_) => navigate("/login", Default::default()),
    });

    view! { <LoadingScreen message="Opening Salvage Cloud"/> }
}

#[component]
fn NotFoundPage() -> impl IntoView {
    view! {
        <main id="main-content" class="standalone-page">
            <div class="standalone-card not-found-card">
                <span class="eyebrow">"404 · Lost in the cloud"</span>
                <h1>"This page drifted away."</h1>
                <p>"The address may be outdated, but your drive is right where you left it."</p>
                <a class="button button-primary" href="/drive">"Back to my drive"</a>
            </div>
        </main>
    }
}
