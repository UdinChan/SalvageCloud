use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use salvage_protocol::{DriveFile, FileKind};
use uuid::Uuid;

use super::fixture::{FixtureFactory, FixtureState};
use super::{
    TelegramUser,
    bots::{BotFactory, BotTransport},
};
use crate::{CoreError, Result};

pub const FIXTURE_BOT_TOKEN: &str = "fixture-bot-token";

#[derive(Clone)]
pub struct FixtureBotFactory {
    accounts: Arc<DashMap<i64, Arc<FixtureState>>>,
}

impl FixtureBotFactory {
    pub fn new(factory: &FixtureFactory) -> Self {
        Self {
            accounts: factory.accounts(),
        }
    }
}

struct FixtureBotTransport {
    accounts: Arc<DashMap<i64, Arc<FixtureState>>>,
    user: TelegramUser,
}

fn bot_user() -> TelegramUser {
    TelegramUser {
        id: 9_000_001,
        display_name: "Salvage Fixture Bot".to_string(),
    }
}

fn destination(
    accounts: &DashMap<i64, Arc<FixtureState>>,
    folder_id: &str,
) -> Option<Arc<FixtureState>> {
    accounts.iter().find_map(|entry| {
        let state = entry.value();
        state
            .folders
            .read()
            .expect("fixture bot folders")
            .contains_key(folder_id)
            .then(|| state.clone())
    })
}

#[async_trait]
impl BotFactory for FixtureBotFactory {
    async fn sign_in(&self, token: &str) -> Result<Arc<dyn BotTransport>> {
        if token != FIXTURE_BOT_TOKEN {
            return Err(CoreError::Unauthorized);
        }
        Ok(Arc::new(FixtureBotTransport {
            accounts: self.accounts.clone(),
            user: bot_user(),
        }))
    }

    async fn restore(&self, session: &[u8], _token: &str) -> Result<Arc<dyn BotTransport>> {
        let user: TelegramUser =
            serde_json::from_slice(session).map_err(|_| CoreError::Unauthorized)?;
        if user.id != bot_user().id {
            return Err(CoreError::Unauthorized);
        }
        Ok(Arc::new(FixtureBotTransport {
            accounts: self.accounts.clone(),
            user,
        }))
    }
}

#[async_trait]
impl BotTransport for FixtureBotTransport {
    fn self_user(&self) -> TelegramUser {
        self.user.clone()
    }

    fn bot_username(&self) -> Option<String> {
        Some("salvage_fixture_bot".to_string())
    }

    async fn export_session(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(&self.user).map_err(|error| CoreError::Internal(error.to_string()))
    }

    async fn can_upload(&self, folder_id: &str) -> Result<bool> {
        let Some(state) = destination(&self.accounts, folder_id) else {
            return Ok(false);
        };
        let folders = state.folders.read().expect("fixture bot folders");
        let folder = folders.get(folder_id).ok_or(CoreError::NotFound)?;
        Ok(folder.name != "No bot access")
    }

    async fn publish_file(
        &self,
        source: &Path,
        folder_id: &str,
        name: &str,
        mime_type: &str,
    ) -> Result<DriveFile> {
        if !self.can_upload(folder_id).await? {
            return Err(CoreError::Unauthorized);
        }
        let state = destination(&self.accounts, folder_id).ok_or(CoreError::NotFound)?;
        let bytes = tokio::fs::read(source).await?;
        let file = DriveFile {
            id: format!("bot-file-{}", Uuid::new_v4()),
            folder_id: Some(folder_id.to_string()),
            name: name.to_string(),
            mime_type: mime_type.to_string(),
            size: bytes.len() as u64,
            kind: if mime_type.starts_with("image/") {
                FileKind::Image
            } else {
                FileKind::Document
            },
            protected: name.ends_with(".tdenc2") || name.ends_with(".tdenc"),
            modified_at: Utc::now(),
        };
        state
            .files
            .write()
            .expect("fixture bot files")
            .insert(file.id.clone(), file.clone());
        state
            .contents
            .write()
            .expect("fixture bot contents")
            .insert(file.id.clone(), bytes);
        Ok(file)
    }
}
