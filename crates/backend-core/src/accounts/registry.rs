use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use salvage_protocol::{AccountInfo, ServerEvent};
use tokio::sync::{Mutex, RwLock, broadcast};
use uuid::Uuid;

use crate::{
    CoreError, Result,
    bot_service::BotService,
    store::WorkspaceStore,
    telegram::{TelegramFactory, TelegramTransport, bots::BotFactory},
};

use super::SessionCipher;

pub struct AccountContext {
    info: AccountInfo,
    generation: AtomicU64,
    transport: RwLock<Option<Arc<dyn TelegramTransport>>>,
    workspace: WorkspaceStore,
    bots: BotService,
    account_dir: PathBuf,
    channel_part_limit: u64,
    events: broadcast::Sender<ServerEvent>,
}

impl AccountContext {
    pub fn info(&self) -> &AccountInfo {
        &self.info
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn workspace(&self) -> &WorkspaceStore {
        &self.workspace
    }

    pub fn bots(&self) -> &BotService {
        &self.bots
    }

    pub fn transfer_path(&self, id: Uuid) -> PathBuf {
        self.account_dir
            .join("transfers")
            .join(format!("{id}.payload"))
    }

    pub fn channel_part_limit(&self) -> u64 {
        self.channel_part_limit
    }

    pub async fn transport(&self) -> Result<Arc<dyn TelegramTransport>> {
        self.transport
            .read()
            .await
            .clone()
            .ok_or(CoreError::Unauthorized)
    }

    pub async fn set_transport(&self, transport: Arc<dyn TelegramTransport>) -> Result<()> {
        let user = transport.self_user().ok_or(CoreError::Unauthorized)?;
        if user.id.to_string() != self.info.telegram_user_id {
            return Err(CoreError::Unauthorized);
        }
        *self.transport.write().await = Some(transport);
        Ok(())
    }

    pub fn subscribe(&self) -> broadcast::Receiver<ServerEvent> {
        self.events.subscribe()
    }

    pub fn notify(&self, event: ServerEvent) {
        let _ = self.events.send(event);
    }

    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.notify(ServerEvent::AccountRevoked);
    }
}

pub struct AccountRegistry {
    contexts: Mutex<HashMap<Uuid, Arc<AccountContext>>>,
    data_root: PathBuf,
    factory: Arc<dyn TelegramFactory>,
    bot_factory: Arc<dyn BotFactory>,
    sessions: SessionCipher,
    channel_part_limit: u64,
}

impl AccountRegistry {
    pub fn new(
        data_root: &Path,
        factory: Arc<dyn TelegramFactory>,
        bot_factory: Arc<dyn BotFactory>,
        sessions: SessionCipher,
        channel_part_limit: u64,
    ) -> Self {
        Self {
            contexts: Mutex::new(HashMap::new()),
            data_root: data_root.to_path_buf(),
            factory,
            bot_factory,
            sessions,
            channel_part_limit,
        }
    }

    pub fn account_dir(&self, account_id: Uuid) -> PathBuf {
        self.data_root.join("accounts").join(account_id.to_string())
    }

    pub async fn open_workspace(&self, info: AccountInfo) -> Result<Arc<AccountContext>> {
        self.open_inner(info, false).await
    }

    pub async fn open(&self, info: AccountInfo) -> Result<Arc<AccountContext>> {
        self.open_inner(info, true).await
    }

    async fn open_inner(
        &self,
        info: AccountInfo,
        restore_transport: bool,
    ) -> Result<Arc<AccountContext>> {
        let mut contexts = self.contexts.lock().await;
        if let Some(context) = contexts.get(&info.id) {
            return Ok(context.clone());
        }
        let account_dir = self.account_dir(info.id);
        let workspace = WorkspaceStore::open(&account_dir.join("workspace.db")).await?;
        let saved = self.sessions.load(&account_dir).await?;
        let transport = if restore_transport {
            match saved {
                Some(bytes) => {
                    let transport = self.factory.restore(&bytes).await?;
                    let user = transport.self_user().ok_or(CoreError::Unauthorized)?;
                    if user.id.to_string() != info.telegram_user_id {
                        return Err(CoreError::Unauthorized);
                    }
                    transport.bind_persistent_session(&account_dir)?;
                    Some(transport)
                }
                None => None,
            }
        } else {
            None
        };
        let (events, _) = broadcast::channel(128);
        let bots = BotService::new(
            self.bot_factory.clone(),
            workspace.clone(),
            self.sessions.clone(),
        );
        let context = Arc::new(AccountContext {
            info,
            generation: AtomicU64::new(1),
            transport: RwLock::new(transport),
            workspace,
            bots,
            account_dir,
            channel_part_limit: self.channel_part_limit,
            events,
        });
        contexts.insert(context.info.id, context.clone());
        Ok(context)
    }

    pub async fn open_with_transport(
        &self,
        info: AccountInfo,
        transport: Arc<dyn TelegramTransport>,
    ) -> Result<Arc<AccountContext>> {
        let context = self.open(info).await?;
        context.set_transport(transport.clone()).await?;
        transport.bind_persistent_session(&self.account_dir(context.info.id))?;
        Ok(context)
    }

    pub async fn revoke(&self, account_id: Uuid) -> Result<()> {
        let context = self.contexts.lock().await.get(&account_id).cloned();
        let mut logout_result = Ok(());
        if let Some(context) = context {
            context.invalidate();
            context.bots.clear().await;
            let transport = context.transport.write().await.take();
            if let Some(transport) = transport {
                logout_result = transport.logout().await;
            }
        }
        if logout_result.is_err() {
            tracing::warn!(
                "Telegram did not confirm remote sign-out; local session cleanup completed"
            );
        }
        self.sessions.remove(&self.account_dir(account_id)).await?;
        Ok(())
    }
}
