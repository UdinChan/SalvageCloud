use std::{collections::HashMap, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use salvage_protocol::{AddBotTokenRequest, BotTokenInfo, DriveFile};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

use crate::{
    CoreError, Result,
    accounts::SessionCipher,
    store::{StoredBotToken, WorkspaceStore},
    telegram::{
        TelegramTransport,
        bots::{BotFactory, BotTransport},
    },
};

pub struct BotService {
    factory: Arc<dyn BotFactory>,
    workspace: WorkspaceStore,
    cipher: SessionCipher,
    clients: Mutex<HashMap<Uuid, Arc<dyn BotTransport>>>,
    load: Mutex<HashMap<Uuid, usize>>,
    rotation: std::sync::atomic::AtomicU64,
    upload_lock: Semaphore,
}

impl BotService {
    pub fn new(
        factory: Arc<dyn BotFactory>,
        workspace: WorkspaceStore,
        cipher: SessionCipher,
    ) -> Self {
        Self {
            factory,
            workspace,
            cipher,
            clients: Mutex::new(HashMap::new()),
            load: Mutex::new(HashMap::new()),
            rotation: std::sync::atomic::AtomicU64::new(0),
            upload_lock: Semaphore::new(1),
        }
    }

    pub async fn list(&self) -> Result<Vec<BotTokenInfo>> {
        Ok(self
            .workspace
            .bot_tokens()
            .await?
            .into_iter()
            .map(|record| record.info)
            .collect())
    }

    pub async fn add(
        &self,
        request: AddBotTokenRequest,
        user_transport: Arc<dyn TelegramTransport>,
    ) -> Result<BotTokenInfo> {
        let label = request.label.trim();
        if label.is_empty() || label.chars().count() > 80 {
            return Err(CoreError::InvalidInput(
                "bot labels must contain 1–80 characters".to_string(),
            ));
        }
        let token = request.token.trim();
        if token.is_empty() || token.len() > 256 || token.chars().any(char::is_whitespace) {
            return Err(CoreError::InvalidInput(
                "the bot token is invalid".to_string(),
            ));
        }
        let transport = self.factory.sign_in(token).await?;
        let user = transport.self_user();
        if self
            .list()
            .await?
            .iter()
            .any(|bot| bot.bot_user_id == user.id.to_string())
        {
            return Err(CoreError::Conflict(
                "this bot is already connected".to_string(),
            ));
        }
        let session = transport.export_session().await?;
        let bot_username = transport.bot_username().ok_or_else(|| {
            CoreError::InvalidInput(
                "the bot must have a public username for provisioning".to_string(),
            )
        })?;
        for folder in user_transport.list_folders(None).await? {
            user_transport
                .provision_bot(&folder.id, &bot_username)
                .await?;
        }
        let info = BotTokenInfo {
            id: Uuid::new_v4(),
            label: label.to_string(),
            bot_user_id: user.id.to_string(),
            bot_username: transport.bot_username(),
            created_at: chrono::Utc::now(),
        };
        self.workspace
            .put_bot_token(&StoredBotToken {
                info: info.clone(),
                token_envelope: BASE64.encode(self.cipher.seal(token.as_bytes())?),
                session_envelope: BASE64.encode(self.cipher.seal(&session)?),
            })
            .await?;
        Ok(info)
    }

    pub async fn remove(&self, id: Uuid) -> Result<()> {
        if self.workspace.bot_token(id).await?.is_none() {
            return Err(CoreError::NotFound);
        }
        self.workspace.delete_bot_token(id).await?;
        self.clients.lock().await.remove(&id);
        Ok(())
    }

    pub async fn provision(
        &self,
        id: Uuid,
        user_transport: Arc<dyn TelegramTransport>,
    ) -> Result<()> {
        let record = self
            .workspace
            .bot_token(id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let username = record.info.bot_username.ok_or_else(|| {
            CoreError::InvalidInput(
                "the bot must have a public username for provisioning".to_string(),
            )
        })?;
        for folder in user_transport.list_folders(None).await? {
            user_transport.provision_bot(&folder.id, &username).await?;
        }
        Ok(())
    }

    pub async fn clear(&self) {
        self.clients.lock().await.clear();
    }

    pub async fn validate_upload(&self, id: Uuid, folder_id: Option<&str>) -> Result<()> {
        let folder_id = folder_id.ok_or_else(|| {
            CoreError::InvalidInput(
                "bots can publish only to channels/groups, not Saved Messages".to_string(),
            )
        })?;
        let transport = self.transport(id).await?;
        if !transport.can_upload(folder_id).await? {
            return Err(CoreError::Conflict(
                "the selected bot is not an administrator with posting rights in this channel"
                    .to_string(),
            ));
        }
        Ok(())
    }

    pub async fn select_upload_bot(&self, folder_id: Option<&str>) -> Result<Uuid> {
        let bots = self.list().await?;
        if bots.is_empty() {
            return Err(CoreError::Conflict(
                "add a channel bot before using automatic selection".to_string(),
            ));
        }
        let offset = self
            .rotation
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as usize;
        let mut candidates = Vec::new();
        for bot in bots {
            if self.validate_upload(bot.id, folder_id).await.is_ok() {
                let load = self.load.lock().await.get(&bot.id).copied().unwrap_or(0);
                candidates.push((bot.id, load));
            }
        }
        if candidates.is_empty() {
            return Err(CoreError::Conflict(
                "no bot currently has administrator posting rights in this channel".to_string(),
            ));
        }
        let start = offset % candidates.len();
        let (selected, _) = candidates[start..]
            .iter()
            .chain(&candidates[..start])
            .min_by_key(|(_, load)| *load)
            .expect("eligible bots present");
        Ok(*selected)
    }

    pub async fn publish(
        &self,
        id: Uuid,
        source: &std::path::Path,
        folder_id: Option<&str>,
        name: &str,
        mime_type: &str,
    ) -> Result<DriveFile> {
        let _permit =
            self.upload_lock.acquire().await.map_err(|_| {
                CoreError::Unavailable("bot upload queue is unavailable".to_string())
            })?;
        self.load
            .lock()
            .await
            .entry(id)
            .and_modify(|load| *load += 1)
            .or_insert(1);
        let result = async {
            self.validate_upload(id, folder_id).await?;
            let folder_id = folder_id.ok_or(CoreError::NotFound)?;
            let transport = self.transport(id).await?;
            let file = transport
                .publish_file(source, folder_id, name, mime_type)
                .await?;
            self.persist_session(id, transport).await?;
            Ok(file)
        }
        .await;
        self.load
            .lock()
            .await
            .entry(id)
            .and_modify(|load| *load = load.saturating_sub(1))
            .or_insert(0);
        result
    }

    async fn transport(&self, id: Uuid) -> Result<Arc<dyn BotTransport>> {
        if let Some(client) = self.clients.lock().await.get(&id).cloned() {
            return Ok(client);
        }
        let record = self
            .workspace
            .bot_token(id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let session_envelope = BASE64
            .decode(&record.session_envelope)
            .map_err(|_| CoreError::Unauthorized)?;
        let session = self.cipher.open(&session_envelope)?;
        let token_envelope = BASE64
            .decode(&record.token_envelope)
            .map_err(|_| CoreError::Unauthorized)?;
        let token = self.cipher.open(&token_envelope)?;
        let token = String::from_utf8(token.to_vec()).map_err(|_| CoreError::Unauthorized)?;
        let restored = self.factory.restore(&session, &token).await;
        let transport = match restored {
            Ok(transport) => transport,
            Err(CoreError::Unauthorized) => self.factory.sign_in(&token).await?,
            Err(error) => return Err(error),
        };
        if transport.self_user().id.to_string() != record.info.bot_user_id {
            return Err(CoreError::Unauthorized);
        }
        self.clients.lock().await.insert(id, transport.clone());
        Ok(transport)
    }

    async fn persist_session(&self, id: Uuid, transport: Arc<dyn BotTransport>) -> Result<()> {
        let session = transport.export_session().await?;
        self.workspace
            .update_bot_session(id, BASE64.encode(self.cipher.seal(&session)?))
            .await
    }
}
