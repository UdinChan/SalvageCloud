use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use grammers_client::Client;
use grammers_mtsender::{ConnectionParams, SenderPool};
use salvage_protocol::{DriveFile, FileKind};
use tokio::sync::oneshot;

use super::{
    TelegramUser,
    live::parse_channel_id,
    persisted_session::{PersistedSession, session_data_from_slice},
};
use crate::{CoreError, Result, accounts::SessionCipher};

#[derive(serde::Deserialize)]
struct BotApiResponse<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
}

#[derive(serde::Deserialize)]
struct ChatMember {
    status: String,
}

#[derive(serde::Deserialize)]
struct BotMessage {
    message_id: i32,
    date: i64,
    document: Option<BotDocument>,
}

#[derive(serde::Deserialize)]
struct BotDocument {
    file_name: Option<String>,
    mime_type: Option<String>,
    file_size: Option<u64>,
}

#[async_trait]
pub trait BotTransport: Send + Sync {
    fn self_user(&self) -> TelegramUser;
    fn bot_username(&self) -> Option<String>;
    async fn export_session(&self) -> Result<Vec<u8>>;
    async fn can_upload(&self, folder_id: &str) -> Result<bool>;
    async fn publish_file(
        &self,
        source: &Path,
        folder_id: &str,
        name: &str,
        mime_type: &str,
    ) -> Result<DriveFile>;
}

#[async_trait]
pub trait BotFactory: Send + Sync {
    async fn sign_in(&self, token: &str) -> Result<Arc<dyn BotTransport>>;
    async fn restore(&self, session: &[u8], token: &str) -> Result<Arc<dyn BotTransport>>;
}

pub struct LiveBotFactory {
    api_id: i32,
    api_hash: String,
    sessions: SessionCipher,
}

impl LiveBotFactory {
    pub fn new(api_id: i32, api_hash: String, sessions: SessionCipher) -> Self {
        Self {
            api_id,
            api_hash,
            sessions,
        }
    }

    async fn connect(&self, session: Arc<PersistedSession>) -> (Client, oneshot::Sender<()>) {
        let pool =
            SenderPool::with_configuration(session, self.api_id, ConnectionParams::default());
        let client = Client::new(&pool);
        let SenderPool { runner, .. } = pool;
        let (shutdown, receiver) = oneshot::channel();
        tokio::spawn(async move {
            tokio::select! {
                _ = runner.run() => {},
                _ = receiver => {},
            }
        });
        (client, shutdown)
    }
}

fn bot_api_client() -> reqwest::Client {
    reqwest::Client::builder()
        .local_address(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .expect("build Telegram Bot API client")
}

struct LiveBotTransport {
    client: Client,
    session: Arc<PersistedSession>,
    user: TelegramUser,
    username: Option<String>,
    token: zeroize::Zeroizing<String>,
    bot_api: reqwest::Client,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}

impl LiveBotTransport {
    fn stop(&self) {
        let _ = self.session.flush();
        if let Some(shutdown) = self.shutdown.lock().expect("bot shutdown").take() {
            let _ = shutdown.send(());
        }
        self.client.disconnect();
    }
}

impl Drop for LiveBotTransport {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait]
impl BotFactory for LiveBotFactory {
    async fn sign_in(&self, token: &str) -> Result<Arc<dyn BotTransport>> {
        let session = Arc::new(PersistedSession::new(self.sessions.clone(), None));
        let (client, shutdown) = self.connect(session.clone()).await;
        let user = client
            .bot_sign_in(token, &self.api_hash)
            .await
            .map_err(network_error)?;
        let username = user.username().map(str::to_string);
        let user = TelegramUser {
            id: user.bare_id(),
            display_name: user.full_name(),
        };
        Ok(Arc::new(LiveBotTransport {
            client,
            session,
            user,
            username,
            token: zeroize::Zeroizing::new(token.to_string()),
            bot_api: bot_api_client(),
            shutdown: Mutex::new(Some(shutdown)),
        }))
    }

    async fn restore(&self, session: &[u8], token: &str) -> Result<Arc<dyn BotTransport>> {
        let data = session_data_from_slice(session)?;
        let session = Arc::new(PersistedSession::new(self.sessions.clone(), Some(data)));
        let (client, shutdown) = self.connect(session.clone()).await;
        let user = client.get_me().await.map_err(|_| CoreError::Unauthorized)?;
        let username = user.username().map(str::to_string);
        let user = TelegramUser {
            id: user.bare_id(),
            display_name: user.full_name(),
        };
        Ok(Arc::new(LiveBotTransport {
            client,
            session,
            user,
            username,
            token: zeroize::Zeroizing::new(token.to_string()),
            bot_api: bot_api_client(),
            shutdown: Mutex::new(Some(shutdown)),
        }))
    }
}

#[async_trait]
impl BotTransport for LiveBotTransport {
    fn self_user(&self) -> TelegramUser {
        self.user.clone()
    }

    fn bot_username(&self) -> Option<String> {
        self.username.clone()
    }

    async fn export_session(&self) -> Result<Vec<u8>> {
        self.session.export()
    }

    async fn can_upload(&self, folder_id: &str) -> Result<bool> {
        let channel_id = parse_channel_id(folder_id)?;
        let response = self
            .bot_api
            .get(format!(
                "https://api.telegram.org/bot{}/getChatMember",
                self.token.as_str()
            ))
            .query(&[
                ("chat_id", format!("-100{channel_id}")),
                ("user_id", self.user.id.to_string()),
            ])
            .send()
            .await
            .map_err(|error| {
                let mut details = Vec::new();
                let mut source = std::error::Error::source(&error);
                while let Some(cause) = source {
                    details.push(cause.to_string());
                    source = cause.source();
                }
                let detail = if details.is_empty() {
                    "request failed".to_string()
                } else {
                    details.join(": ")
                };
                CoreError::Unavailable(format!("Telegram bot permission check failed: {detail}"))
            })?;
        let status = response.status();
        let body: BotApiResponse<ChatMember> = response.json().await.map_err(|_| {
            CoreError::Unavailable(
                "Telegram bot permission check returned an invalid response".to_string(),
            )
        })?;
        if !status.is_success() || !body.ok {
            return Ok(false);
        }
        let allowed = body
            .result
            .is_some_and(|member| matches!(member.status.as_str(), "creator" | "administrator"));
        self.session.flush()?;
        Ok(allowed)
    }

    async fn publish_file(
        &self,
        source: &Path,
        folder_id: &str,
        name: &str,
        mime_type: &str,
    ) -> Result<DriveFile> {
        let size = tokio::fs::metadata(source).await?.len();
        if size > 50 * 1024 * 1024 {
            return Err(CoreError::Conflict(
                "Bot API uploads are limited to 50 MiB. Use your personal account for larger files."
                    .to_string(),
            ));
        }
        let channel_id = parse_channel_id(folder_id)?;
        let part = reqwest::multipart::Part::file(source)
            .await
            .map_err(|_| CoreError::Unavailable("could not stage the bot upload".to_string()))?
            .file_name(name.to_string())
            .mime_str(mime_type)
            .map_err(|_| CoreError::InvalidInput("invalid bot upload media type".to_string()))?;
        let form = reqwest::multipart::Form::new()
            .text("chat_id", format!("-100{channel_id}"))
            .text("caption", name.to_string())
            .part("document", part);
        let response = self
            .bot_api
            .post(format!(
                "https://api.telegram.org/bot{}/sendDocument",
                self.token.as_str()
            ))
            .multipart(form)
            .send()
            .await
            .map_err(|_| CoreError::Unavailable("Telegram bot upload failed".to_string()))?;
        let status = response.status();
        let body: BotApiResponse<BotMessage> = response.json().await.map_err(|_| {
            CoreError::Unavailable("Telegram bot upload returned an invalid response".to_string())
        })?;
        if !status.is_success() || !body.ok {
            return Err(CoreError::Conflict(
                body.description
                    .unwrap_or_else(|| "Telegram rejected the bot upload".to_string()),
            ));
        }
        let message = body.result.ok_or_else(|| {
            CoreError::Unavailable("Telegram did not return the bot-uploaded message".to_string())
        })?;
        let document = message.document.ok_or_else(|| {
            CoreError::Unavailable("Telegram did not return the bot-uploaded document".to_string())
        })?;
        let file_name = document.file_name.unwrap_or_else(|| name.to_string());
        let protected = file_name.ends_with(".tdenc2") || file_name.ends_with(".tdenc");
        let mime_type = document.mime_type.unwrap_or_else(|| mime_type.to_string());
        let kind = if mime_type.starts_with("image/") {
            FileKind::Image
        } else if mime_type.starts_with("video/") {
            FileKind::Video
        } else if mime_type.starts_with("audio/") {
            FileKind::Audio
        } else if matches!(
            mime_type.as_str(),
            "application/zip" | "application/x-7z-compressed" | "application/x-rar-compressed"
        ) {
            FileKind::Archive
        } else if mime_type == "text/plain" || mime_type == "application/pdf" {
            FileKind::Document
        } else {
            FileKind::Other
        };
        let modified_at = chrono::TimeZone::timestamp_opt(&chrono::Utc, message.date, 0)
            .single()
            .unwrap_or_else(chrono::Utc::now);
        self.session.flush()?;
        Ok(DriveFile {
            id: format!("{folder_id}:{}", message.message_id),
            folder_id: Some(folder_id.to_string()),
            name: file_name,
            mime_type,
            size: document.file_size.unwrap_or(size),
            kind,
            protected,
            modified_at,
        })
    }
}

fn network_error(error: grammers_mtsender::InvocationError) -> CoreError {
    let detail = match error {
        grammers_mtsender::InvocationError::Rpc(error) => error.name,
        grammers_mtsender::InvocationError::Io(_) => "connection failed".to_string(),
        grammers_mtsender::InvocationError::Deserialize(_) => {
            "invalid Telegram response".to_string()
        }
        grammers_mtsender::InvocationError::Transport(_) => "transport failed".to_string(),
        grammers_mtsender::InvocationError::Dropped => "request cancelled".to_string(),
        grammers_mtsender::InvocationError::InvalidDc => "invalid datacenter".to_string(),
        grammers_mtsender::InvocationError::Authentication(_) => {
            "authentication failed".to_string()
        }
    };
    if matches!(
        detail.as_str(),
        "USER_NOT_PARTICIPANT" | "CHANNEL_PRIVATE" | "CHAT_WRITE_FORBIDDEN"
    ) {
        CoreError::Conflict(
            "the selected bot is not an administrator with posting rights in this channel"
                .to_string(),
        )
    } else {
        CoreError::Unavailable(format!("Telegram bot request failed: {detail}"))
    }
}
