use leptos::prelude::*;
use leptos::task::spawn_local;
use salvage_protocol::{AccountInfo, SessionResponse};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::api;

const PREFERENCES_KEY: &str = "salvage-cloud.browser-preferences.v1";

#[derive(Clone)]
pub enum SessionStatus {
    Loading,
    Anonymous,
    Authenticated(SessionResponse),
    Error(String),
}

#[derive(Clone, Copy)]
pub struct SessionState {
    pub status: RwSignal<SessionStatus>,
    pub generation: RwSignal<u64>,
    pub notice: RwSignal<Option<String>>,
}

impl SessionState {
    pub fn new() -> Self {
        Self {
            status: RwSignal::new(SessionStatus::Loading),
            generation: RwSignal::new(0),
            notice: RwSignal::new(None),
        }
    }

    pub fn restore_session(self) {
        let generation = self.generation.get_untracked().wrapping_add(1);
        self.generation.set(generation);
        self.status.set(SessionStatus::Loading);

        spawn_local(async move {
            let result = api::get_session().await;
            if self.generation.get_untracked() != generation {
                return;
            }
            match result {
                Ok(Some(session)) => self.status.set(SessionStatus::Authenticated(session)),
                Ok(None) => self.status.set(SessionStatus::Anonymous),
                Err(error) => self.status.set(SessionStatus::Error(error.message)),
            }
        });
    }

    pub fn login_generation(self) -> u64 {
        self.generation.get_untracked()
    }

    pub fn authenticate(self, session: SessionResponse, generation: u64) -> bool {
        if self.generation.get_untracked() != generation {
            return false;
        }
        self.notice.set(None);
        self.status.set(SessionStatus::Authenticated(session));
        true
    }

    pub fn authenticated_session(self) -> Option<SessionResponse> {
        match self.status.get() {
            SessionStatus::Authenticated(session) => Some(session),
            _ => None,
        }
    }

    pub fn is_current(self, generation: u64, account_id: Uuid) -> bool {
        self.generation.get_untracked() == generation
            && self.account_id_untracked() == Some(account_id)
    }

    fn account_id_untracked(self) -> Option<Uuid> {
        match self.status.get_untracked() {
            SessionStatus::Authenticated(session) => Some(session.account.id),
            _ => None,
        }
    }

    pub fn expire(self, generation: u64, account_id: Uuid) {
        if !self.is_current(generation, account_id) {
            return;
        }
        self.generation
            .update(|value| *value = value.wrapping_add(1));
        self.notice.set(Some(
            "Your session expired. Please sign in again.".to_owned(),
        ));
        self.status.set(SessionStatus::Anonymous);
    }

    pub fn logout(self) {
        let csrf_token = match self.status.get_untracked() {
            SessionStatus::Authenticated(session) => Some(session.csrf_token),
            _ => None,
        };
        self.generation
            .update(|value| *value = value.wrapping_add(1));
        let generation = self.generation.get_untracked();
        self.status.set(SessionStatus::Anonymous);
        self.notice.set(None);

        if let Some(csrf_token) = csrf_token {
            spawn_local(async move {
                if let Err(error) = api::logout(&csrf_token).await
                    && self.generation.get_untracked() == generation
                {
                    self.notice.set(Some(format!(
                        "You’re signed out of this tab, but the server couldn’t confirm logout. {}. Reload before signing in again.",
                        error.message
                    )));
                }
            });
        }
    }

    pub fn account(self) -> Option<AccountInfo> {
        self.authenticated_session().map(|session| session.account)
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Theme {
    #[default]
    System,
    Light,
    Dark,
}

impl Theme {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Density {
    #[default]
    Comfortable,
    Compact,
}

impl Density {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Comfortable => "comfortable",
            Self::Compact => "compact",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ViewMode {
    #[default]
    Grid,
    List,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct BrowserPreferences {
    pub theme: Theme,
    pub density: Density,
    pub view_mode: ViewMode,
    pub show_file_details: bool,
}

impl BrowserPreferences {
    fn load() -> Self {
        let Some(storage) =
            web_sys::window().and_then(|window| window.local_storage().ok().flatten())
        else {
            return Self::default();
        };
        storage
            .get_item(PREFERENCES_KEY)
            .ok()
            .flatten()
            .and_then(|value| serde_json::from_str(&value).ok())
            .unwrap_or_default()
    }

    fn save(&self) {
        if let Some(storage) =
            web_sys::window().and_then(|window| window.local_storage().ok().flatten())
            && let Ok(value) = serde_json::to_string(self)
        {
            let _ = storage.set_item(PREFERENCES_KEY, &value);
        }
    }
}

#[derive(Clone, Copy)]
pub struct Preferences {
    pub value: RwSignal<BrowserPreferences>,
}

impl Preferences {
    pub fn new() -> Self {
        Self {
            value: RwSignal::new(BrowserPreferences::load()),
        }
    }

    fn update(self, update: impl FnOnce(&mut BrowserPreferences)) {
        let mut preferences = self.value.get_untracked();
        update(&mut preferences);
        preferences.save();
        self.value.set(preferences);
    }

    pub fn set_theme(self, theme: Theme) {
        self.update(|preferences| preferences.theme = theme);
    }

    pub fn set_density(self, density: Density) {
        self.update(|preferences| preferences.density = density);
    }

    pub fn set_view_mode(self, view_mode: ViewMode) {
        self.update(|preferences| preferences.view_mode = view_mode);
    }

    pub fn set_show_file_details(self, show: bool) {
        self.update(|preferences| preferences.show_file_details = show);
    }
}
