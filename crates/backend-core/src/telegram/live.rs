use std::{
    path::Path,
    sync::{Arc, Mutex, RwLock},
    time::Duration,
};

use async_trait::async_trait;
use grammers_client::InputMessage;
use grammers_client::{
    Client, SignInError,
    types::{LoginToken, Media, Message, PasswordToken, Peer, User},
};
use grammers_mtsender::{ConnectionParams, SenderPool};
use grammers_session::{
    Session,
    types::{ChannelKind, PeerAuth, PeerId, PeerInfo, PeerRef, UpdateState, UpdatesState},
};
use grammers_tl_types as tl;
use salvage_protocol::{DriveFile, FileKind, Folder};
use tokio::sync::{Mutex as AsyncMutex, oneshot};

use crate::{CoreError, Result, accounts::SessionCipher};

use super::{
    PhoneAttempt, QrCodeAttempt, QrPoll, TelegramFactory, TelegramTransport, TelegramUser,
    TransportLogin, login_qr_svg,
    persisted_session::{PersistedSession, session_data_from_slice},
    resumable::ResumableUploads,
};

const MAX_HISTORY_MESSAGES: usize = 10_000;

pub struct LiveTelegramFactory {
    api_id: i32,
    api_hash: String,
    sessions: SessionCipher,
}

impl LiveTelegramFactory {
    pub fn new(api_id: i32, api_hash: String, sessions: SessionCipher) -> Self {
        Self {
            api_id,
            api_hash,
            sessions,
        }
    }

    async fn connect(
        &self,
        session: Arc<PersistedSession>,
    ) -> Result<(Client, oneshot::Sender<()>)> {
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
        Ok((client, shutdown))
    }
}

enum LiveLogin {
    Code(LoginToken),
    Password(Box<PasswordToken>),
    Qr { token: Vec<u8>, dc_id: Option<i32> },
}

enum QrStep {
    Token { token: Vec<u8>, dc_id: Option<i32> },
    Complete(TransportLogin),
}

struct LiveTransport {
    client: Client,
    session: Arc<PersistedSession>,
    api_id: i32,
    api_hash: String,
    login: AsyncMutex<Option<LiveLogin>>,
    user: RwLock<Option<TelegramUser>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    resumable: ResumableUploads,
}

impl LiveTransport {
    fn new(
        client: Client,
        session: Arc<PersistedSession>,
        shutdown: oneshot::Sender<()>,
        api_id: i32,
        api_hash: String,
    ) -> Self {
        Self {
            client,
            session,
            api_id,
            api_hash,
            login: AsyncMutex::new(None),
            user: RwLock::new(None),
            shutdown: Mutex::new(Some(shutdown)),
            resumable: ResumableUploads::new(),
        }
    }

    fn set_user(&self, user: grammers_client::types::User) {
        *self.user.write().expect("live user") = Some(TelegramUser {
            id: user.bare_id(),
            display_name: user.full_name(),
        });
    }

    fn stop(&self) {
        let _ = self.session.flush();
        if let Some(shutdown) = self.shutdown.lock().expect("live shutdown").take() {
            let _ = shutdown.send(());
        }
        self.client.disconnect();
    }

    async fn complete_qr_success(
        &self,
        success: tl::types::auth::LoginTokenSuccess,
    ) -> Result<TransportLogin> {
        let tl::enums::auth::Authorization::Authorization(authorization) = success.authorization
        else {
            return Err(CoreError::InvalidInput(
                "register this phone in an official Telegram app first".to_string(),
            ));
        };
        let user = User::from_raw(authorization.user);
        let update_state = self
            .client
            .invoke(&tl::functions::updates::GetState {})
            .await
            .ok();
        self.session.cache_peer(&PeerInfo::User {
            id: user.bare_id(),
            auth: Some(PeerAuth::default()),
            bot: Some(user.is_bot()),
            is_self: Some(true),
        });
        if let Some(tl::enums::updates::State::State(state)) = update_state {
            self.session
                .set_update_state(UpdateState::All(UpdatesState {
                    pts: state.pts,
                    qts: state.qts,
                    date: state.date,
                    seq: state.seq,
                    channels: Vec::new(),
                }));
        }
        self.set_user(user);
        Ok(TransportLogin::Authenticated)
    }

    async fn export_qr_token(&self, dc_id: Option<i32>, depth: u8) -> Result<QrStep> {
        if depth > 2 {
            return Err(CoreError::Unavailable(
                "Telegram QR login migrated too many times".to_string(),
            ));
        }
        let request = tl::functions::auth::ExportLoginToken {
            api_id: self.api_id,
            api_hash: self.api_hash.clone(),
            except_ids: Vec::new(),
        };
        let result = match dc_id {
            Some(dc) => self.client.invoke_in_dc(dc, &request).await,
            None => self.client.invoke(&request).await,
        }
        .map_err(map_network_error)?;
        match result {
            tl::enums::auth::LoginToken::Token(token) => Ok(QrStep::Token {
                token: token.token,
                dc_id,
            }),
            tl::enums::auth::LoginToken::MigrateTo(migration) => {
                Box::pin(self.export_qr_token(Some(migration.dc_id), depth + 1)).await
            }
            tl::enums::auth::LoginToken::Success(success) => self
                .complete_qr_success(success)
                .await
                .map(QrStep::Complete),
        }
    }

    async fn peer_info(&self, folder_id: &str) -> Result<PeerInfo> {
        let channel_id = parse_channel_id(folder_id)?;
        let peer_id = PeerId::channel(channel_id);
        if let Some(info) = self.session.peer(peer_id) {
            return Ok(info);
        }
        let mut dialogs = self.client.iter_dialogs();
        while let Some(dialog) = dialogs.next().await.map_err(map_network_error)? {
            if matches!(&dialog.peer, Peer::Channel(channel) if channel.raw.id == channel_id) {
                let info = PeerInfo::from(&dialog.peer);
                self.session.flush()?;
                return Ok(info);
            }
        }
        self.session.flush()?;
        Err(CoreError::NotFound)
    }

    async fn peer_ref(&self, folder_id: Option<&str>) -> Result<PeerRef> {
        match folder_id {
            Some(id) => Ok(PeerRef::from(&self.peer_info(id).await?)),
            None => Ok(PeerRef {
                id: PeerId::self_user(),
                auth: PeerAuth::default(),
            }),
        }
    }

    async fn message_by_id(&self, folder_id: Option<&str>, message_id: i32) -> Result<Message> {
        let peer = self.peer_ref(folder_id).await?;
        if folder_id.is_some() {
            return self
                .client
                .get_messages_by_id(peer, &[message_id])
                .await
                .map_err(map_network_error)?
                .into_iter()
                .flatten()
                .next()
                .ok_or(CoreError::NotFound);
        }

        // Saved Messages needs the same iterator used by listing. Grammers can map the
        // concrete self user and the self-user sentinel differently in get_messages_by_id,
        // causing an existing root message to be filtered out.
        let mut messages = self.client.iter_messages(peer);
        let mut inspected = 0_usize;
        while let Some(message) = messages.next().await.map_err(map_network_error)? {
            if message.id() == message_id {
                return Ok(message);
            }
            inspected += 1;
            if inspected >= MAX_HISTORY_MESSAGES {
                break;
            }
        }
        Err(CoreError::NotFound)
    }

    async fn list_files_in_peer(
        &self,
        folder_id: Option<&str>,
        query: Option<&str>,
    ) -> Result<Vec<DriveFile>> {
        let peer = self.peer_ref(folder_id).await?;
        let needle = query.map(str::to_lowercase);
        let mut messages = self.client.iter_messages(peer);
        let mut files = Vec::new();
        let mut inspected = 0_usize;
        while let Some(message) = messages.next().await.map_err(map_network_error)? {
            inspected += 1;
            if inspected > MAX_HISTORY_MESSAGES {
                break;
            }
            if let Some(file) = file_from_message(&message, folder_id)
                && needle
                    .as_ref()
                    .is_none_or(|needle| file.name.to_lowercase().contains(needle))
            {
                files.push(file);
            }
        }
        self.session.flush()?;
        Ok(files)
    }
}

impl Drop for LiveTransport {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait]
impl TelegramFactory for LiveTelegramFactory {
    async fn begin_phone_login(
        &self,
        phone: &str,
    ) -> Result<(Arc<dyn TelegramTransport>, PhoneAttempt)> {
        let session = Arc::new(PersistedSession::new(self.sessions.clone(), None));
        let (client, shutdown) = self.connect(session.clone()).await?;
        let transport = Arc::new(LiveTransport::new(
            client,
            session,
            shutdown,
            self.api_id,
            self.api_hash.clone(),
        ));
        let token = transport
            .client
            .request_login_code(phone, &self.api_hash)
            .await
            .map_err(map_auth_error)?;
        *transport.login.lock().await = Some(LiveLogin::Code(token));
        Ok((
            transport,
            PhoneAttempt {
                phone_hint: redact_phone(phone),
                code_length: None,
            },
        ))
    }

    async fn begin_qr_login(&self) -> Result<(Arc<dyn TelegramTransport>, QrCodeAttempt)> {
        let session = Arc::new(PersistedSession::new(self.sessions.clone(), None));
        let (client, shutdown) = self.connect(session.clone()).await?;
        let transport = Arc::new(LiveTransport::new(
            client,
            session,
            shutdown,
            self.api_id,
            self.api_hash.clone(),
        ));
        let QrStep::Token { token, dc_id } = transport.export_qr_token(None, 0).await? else {
            return Err(CoreError::Unavailable(
                "Telegram returned an unexpected QR login response".to_string(),
            ));
        };
        let qr_svg = login_qr_svg(&token)?;
        *transport.login.lock().await = Some(LiveLogin::Qr {
            token: token.clone(),
            dc_id,
        });
        Ok((
            transport,
            QrCodeAttempt {
                qr_svg,
                expires_in_seconds: 30,
            },
        ))
    }

    async fn restore(&self, session: &[u8]) -> Result<Arc<dyn TelegramTransport>> {
        let data = session_data_from_slice(session)?;
        let session = Arc::new(PersistedSession::new(self.sessions.clone(), Some(data)));
        let (client, shutdown) = self.connect(session.clone()).await?;
        let transport = Arc::new(LiveTransport::new(
            client,
            session,
            shutdown,
            self.api_id,
            self.api_hash.clone(),
        ));
        let user = transport
            .client
            .get_me()
            .await
            .map_err(|_| CoreError::Unauthorized)?;
        transport.set_user(user);
        Ok(transport)
    }
}

#[async_trait]
impl TelegramTransport for LiveTransport {
    async fn verify_code(&self, code: &str) -> Result<TransportLogin> {
        let state = self.login.lock().await.take();
        let Some(LiveLogin::Code(token)) = state else {
            return Err(CoreError::Unauthorized);
        };
        match self.client.sign_in(&token, code).await {
            Ok(user) => {
                self.set_user(user);
                Ok(TransportLogin::Authenticated)
            }
            Err(SignInError::PasswordRequired(password)) => {
                let hint = password.hint().map(str::to_string);
                *self.login.lock().await = Some(LiveLogin::Password(Box::new(password)));
                Ok(TransportLogin::PasswordRequired {
                    password_hint: hint,
                })
            }
            Err(SignInError::InvalidCode) => {
                *self.login.lock().await = Some(LiveLogin::Code(token));
                Err(CoreError::Unauthorized)
            }
            Err(SignInError::SignUpRequired { .. }) => Err(CoreError::InvalidInput(
                "register this phone in an official Telegram app first".to_string(),
            )),
            Err(SignInError::InvalidPassword) => Err(CoreError::Unauthorized),
            Err(SignInError::Other(error)) => Err(map_auth_error(error)),
        }
    }

    async fn verify_password(&self, password: &str) -> Result<()> {
        let token = {
            let login = self.login.lock().await;
            match login.as_ref() {
                Some(LiveLogin::Password(token)) => token.as_ref().clone(),
                _ => return Err(CoreError::Unauthorized),
            }
        };
        match self.client.check_password(token, password).await {
            Ok(user) => {
                self.set_user(user);
                *self.login.lock().await = None;
                Ok(())
            }
            Err(SignInError::InvalidPassword) => Err(CoreError::Unauthorized),
            Err(_) => Err(CoreError::Unavailable(
                "Telegram cloud-password verification failed".to_string(),
            )),
        }
    }

    async fn poll_qr_login(&self) -> Result<QrPoll> {
        let state = self.login.lock().await.take();
        let Some(LiveLogin::Qr { token, dc_id }) = state else {
            return Err(CoreError::Unauthorized);
        };
        let request = tl::functions::auth::ImportLoginToken { token };
        let result = match dc_id {
            Some(dc) => self.client.invoke_in_dc(dc, &request).await,
            None => self.client.invoke(&request).await,
        }
        .map_err(map_network_error)?;
        match result {
            tl::enums::auth::LoginToken::Token(token) => {
                let qr_svg = login_qr_svg(&token.token)?;
                *self.login.lock().await = Some(LiveLogin::Qr {
                    token: token.token,
                    dc_id,
                });
                Ok(QrPoll::Pending {
                    qr_svg: Some(qr_svg),
                })
            }
            tl::enums::auth::LoginToken::MigrateTo(migration) => {
                match self.export_qr_token(Some(migration.dc_id), 1).await? {
                    QrStep::Token { token, dc_id } => {
                        let qr_svg = login_qr_svg(&token)?;
                        *self.login.lock().await = Some(LiveLogin::Qr { token, dc_id });
                        Ok(QrPoll::Pending {
                            qr_svg: Some(qr_svg),
                        })
                    }
                    QrStep::Complete(login) => Ok(QrPoll::Ready(login)),
                }
            }
            tl::enums::auth::LoginToken::Success(success) => {
                let login = self.complete_qr_success(success).await?;
                Ok(QrPoll::Ready(login))
            }
        }
    }

    fn self_user(&self) -> Option<TelegramUser> {
        self.user.read().expect("live user").clone()
    }

    async fn export_session(&self) -> Result<Vec<u8>> {
        self.session.export()
    }

    fn bind_persistent_session(&self, account_dir: &Path) -> Result<()> {
        self.session.bind(account_dir)?;
        self.resumable.bind(account_dir)
    }

    async fn logout(&self) -> Result<()> {
        let result = tokio::time::timeout(Duration::from_secs(10), self.client.sign_out()).await;
        self.stop();
        *self.user.write().expect("live user") = None;
        match result {
            Ok(Ok(_)) => Ok(()),
            _ => Err(CoreError::Unavailable(
                "Telegram did not confirm remote sign-out; the hosted session was removed"
                    .to_string(),
            )),
        }
    }

    async fn list_folders(&self, parent_id: Option<&str>) -> Result<Vec<Folder>> {
        if parent_id.is_some() {
            return Ok(Vec::new());
        }
        let mut dialogs = self.client.iter_dialogs();
        let mut folders = Vec::new();
        while let Some(dialog) = dialogs.next().await.map_err(map_network_error)? {
            if let Peer::Channel(channel) = dialog.peer
                && let Some(name) = folder_name(&channel.raw.title)
            {
                folders.push(Folder {
                    id: channel.raw.id.to_string(),
                    parent_id: None,
                    name,
                    file_count: 0,
                    active: false,
                    created_at: chrono::Utc::now(),
                });
            }
        }
        self.session.flush()?;
        folders.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(folders)
    }

    async fn create_folder(&self, parent_id: Option<&str>, name: &str) -> Result<Folder> {
        if parent_id.is_some() {
            return Err(CoreError::InvalidInput(
                "Telegram channel folders are top-level".to_string(),
            ));
        }
        let result = self
            .client
            .invoke(&tl::functions::channels::CreateChannel {
                broadcast: true,
                megagroup: false,
                title: format!("{name} [SC]"),
                about:
                    "Salvage Cloud storage folder\n[salvage-cloud-folder]\n[telegram-drive-folder]"
                        .to_string(),
                geo_point: None,
                address: None,
                for_import: false,
                forum: false,
                ttl_period: None,
            })
            .await
            .map_err(map_network_error)?;
        let chats = match result {
            tl::enums::Updates::Updates(updates) => updates.chats,
            tl::enums::Updates::Combined(updates) => updates.chats,
            _ => {
                return Err(CoreError::Unavailable(
                    "Telegram returned an unexpected folder response".to_string(),
                ));
            }
        };
        let channel = chats
            .into_iter()
            .find_map(|chat| match chat {
                tl::enums::Chat::Channel(channel) => Some(channel),
                _ => None,
            })
            .ok_or_else(|| {
                CoreError::Unavailable("Telegram did not return the new folder".to_string())
            })?;
        self.session.cache_peer(&PeerInfo::Channel {
            id: channel.id,
            auth: channel.access_hash.map(PeerAuth::from_hash),
            kind: Some(ChannelKind::Broadcast),
        });
        Ok(Folder {
            id: channel.id.to_string(),
            parent_id: None,
            name: name.to_string(),
            file_count: 0,
            active: false,
            created_at: chrono::Utc::now(),
        })
    }

    async fn rename_folder(&self, id: &str, name: &str) -> Result<Folder> {
        let info = self.peer_info(id).await?;
        let PeerInfo::Channel {
            id: channel_id,
            auth,
            ..
        } = info
        else {
            return Err(CoreError::NotFound);
        };
        self.client
            .invoke(&tl::functions::channels::EditTitle {
                channel: tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id,
                    access_hash: auth.map(|value| value.hash()).unwrap_or_default(),
                }),
                title: format!("{name} [SC]"),
            })
            .await
            .map_err(map_network_error)?;
        Ok(Folder {
            id: id.to_string(),
            parent_id: None,
            name: name.to_string(),
            file_count: 0,
            active: false,
            created_at: chrono::Utc::now(),
        })
    }

    async fn delete_folder(&self, id: &str) -> Result<()> {
        let info = self.peer_info(id).await?;
        let PeerInfo::Channel {
            id: channel_id,
            auth,
            ..
        } = info
        else {
            return Err(CoreError::NotFound);
        };
        self.client
            .invoke(&tl::functions::channels::DeleteChannel {
                channel: tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id,
                    access_hash: auth.map(|value| value.hash()).unwrap_or_default(),
                }),
            })
            .await
            .map_err(map_network_error)?;
        Ok(())
    }

    async fn provision_bot(&self, folder_id: &str, bot_username: &str) -> Result<()> {
        let info = self.peer_info(folder_id).await?;
        let PeerInfo::Channel {
            id: channel_id,
            auth,
            ..
        } = info
        else {
            return Err(CoreError::NotFound);
        };
        let resolved = self
            .client
            .invoke(&tl::functions::contacts::ResolveUsername {
                username: bot_username.trim_start_matches('@').to_string(),
                referer: None,
            })
            .await
            .map_err(map_network_error)?;
        let tl::enums::contacts::ResolvedPeer::Peer(resolved) = resolved;
        let user = resolved
            .users
            .into_iter()
            .find_map(|user| match user {
                tl::enums::User::User(user) => Some(user),
                _ => None,
            })
            .ok_or(CoreError::NotFound)?;
        let user_id = user.id;
        let access_hash = user.access_hash.unwrap_or_default();
        self.client
            .invoke(&tl::functions::channels::EditAdmin {
                channel: tl::enums::InputChannel::Channel(tl::types::InputChannel {
                    channel_id,
                    access_hash: auth.map(|value| value.hash()).unwrap_or_default(),
                }),
                user_id: tl::enums::InputUser::User(tl::types::InputUser {
                    user_id,
                    access_hash,
                }),
                admin_rights: tl::enums::ChatAdminRights::Rights(tl::types::ChatAdminRights {
                    change_info: false,
                    post_messages: true,
                    edit_messages: false,
                    delete_messages: false,
                    ban_users: false,
                    invite_users: false,
                    pin_messages: false,
                    add_admins: false,
                    anonymous: false,
                    manage_call: false,
                    other: false,
                    manage_topics: false,
                    post_stories: false,
                    edit_stories: false,
                    delete_stories: false,
                    manage_direct_messages: false,
                }),
                rank: String::new(),
            })
            .await
            .map_err(map_network_error)?;
        Ok(())
    }

    async fn list_files(
        &self,
        folder_id: Option<&str>,
        query: Option<&str>,
    ) -> Result<Vec<DriveFile>> {
        if folder_id.is_none() && query.is_some() {
            let mut files = self.list_files_in_peer(None, query).await?;
            for folder in self.list_folders(None).await? {
                files.extend(self.list_files_in_peer(Some(&folder.id), query).await?);
            }
            files.sort_by_key(|file| std::cmp::Reverse(file.modified_at));
            return Ok(files);
        }
        self.list_files_in_peer(folder_id, query).await
    }

    async fn delete_file(&self, id: &str) -> Result<()> {
        let (folder_id, message_id) = parse_file_id(id)?;
        let peer = self.peer_ref(folder_id).await?;
        let message = self.message_by_id(folder_id, message_id).await?;
        if file_from_message(&message, folder_id).is_none() {
            return Err(CoreError::NotFound);
        }
        self.client
            .delete_messages(peer, &[message_id])
            .await
            .map_err(map_network_error)?;
        Ok(())
    }

    async fn file_metadata(&self, id: &str) -> Result<DriveFile> {
        let (folder_id, message_id) = parse_file_id(id)?;
        let message = self.message_by_id(folder_id, message_id).await?;
        file_from_message(&message, folder_id).ok_or(CoreError::NotFound)
    }

    async fn publish_file(
        &self,
        source: &Path,
        folder_id: Option<&str>,
        name: &str,
        _mime_type: &str,
    ) -> Result<DriveFile> {
        let prepared = self
            .resumable
            .prepare(&self.client, source, name, folder_id)
            .await?;
        let (uploaded, resume_key) = match prepared {
            Some(prepared) => (prepared.uploaded, Some(prepared.key)),
            None => {
                let size = tokio::fs::metadata(source).await?.len() as usize;
                let mut input = tokio::fs::File::open(source).await?;
                let uploaded = self
                    .client
                    .upload_stream(&mut input, size, name.to_string())
                    .await
                    .map_err(map_io_error)?;
                (uploaded, None)
            }
        };
        let message = self
            .client
            .send_message(
                self.peer_ref(folder_id).await?,
                InputMessage::new().text(name).file(uploaded),
            )
            .await
            .map_err(map_network_error)?;
        if let Some(key) = resume_key
            && self.resumable.finish(&key).await.is_err()
        {
            tracing::warn!("could not clear completed large-upload journal");
        }
        file_from_message(&message, folder_id).ok_or_else(|| {
            CoreError::Unavailable("Telegram did not return the uploaded file".to_string())
        })
    }

    async fn download_file(&self, id: &str, destination: &Path) -> Result<DriveFile> {
        let (folder_id, message_id) = parse_file_id(id)?;
        let message = self.message_by_id(folder_id, message_id).await?;
        let file = file_from_message(&message, folder_id).ok_or(CoreError::NotFound)?;
        let media = message.media().ok_or(CoreError::NotFound)?;
        if matches!(media, Media::Photo(_)) {
            // Progressive photos may arrive in 4 KiB segments. A larger request makes
            // Grammers mistake the first short segment for end-of-file.
            let mut download = self.client.iter_download(&media).chunk_size(4 * 1024);
            let mut output = tokio::fs::File::create(destination)
                .await
                .map_err(map_io_error)?;
            while let Some(chunk) = download.next().await.map_err(map_network_error)? {
                tokio::io::AsyncWriteExt::write_all(&mut output, &chunk)
                    .await
                    .map_err(map_io_error)?;
            }
            tokio::io::AsyncWriteExt::flush(&mut output)
                .await
                .map_err(map_io_error)?;
        } else {
            self.client
                .download_media(&media, destination)
                .await
                .map_err(map_io_error)?;
        }
        Ok(file)
    }
}

fn folder_name(title: &str) -> Option<String> {
    [" [SC]", " [TD]", " [sc]", " [td]"]
        .iter()
        .find_map(|suffix| {
            title
                .strip_suffix(suffix)
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
        })
}

pub(crate) fn file_from_message(message: &Message, folder_id: Option<&str>) -> Option<DriveFile> {
    let media = message.media()?;
    let (name, mime_type, size, protected) = match media {
        Media::Document(document) => {
            let document_name = document.name().to_string();
            let protected = document_name.starts_with("TDENC2")
                || document_name.ends_with(".tdenc2")
                || document_name.ends_with(".tdenc");
            let name = if protected {
                "Encrypted file".to_string()
            } else if message.text().is_empty() {
                document_name
            } else {
                message.text().to_string()
            };
            let mime = document
                .mime_type()
                .unwrap_or("application/octet-stream")
                .to_string();
            (name, mime, document.size().max(0) as u64, protected)
        }
        Media::Photo(photo) => {
            let name = if message.text().is_empty() {
                format!("Photo-{}.jpg", message.id())
            } else {
                message.text().to_string()
            };
            (
                name,
                "image/jpeg".to_string(),
                photo.size().max(0) as u64,
                false,
            )
        }
        _ => return None,
    };
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
    Some(DriveFile {
        id: format!("{}:{}", folder_id.unwrap_or("root"), message.id()),
        folder_id: folder_id.map(str::to_string),
        name,
        mime_type,
        size,
        kind,
        protected,
        modified_at: message.date(),
    })
}

pub(crate) fn parse_channel_id(value: &str) -> Result<i64> {
    let id = value.parse::<i64>().map_err(|_| CoreError::NotFound)?;
    let valid = (1..=997_852_516_352).contains(&id)
        || (1_002_147_483_649..=3_000_000_000_000).contains(&id);
    if valid {
        Ok(id)
    } else {
        Err(CoreError::NotFound)
    }
}

fn parse_file_id(value: &str) -> Result<(Option<&str>, i32)> {
    let (scope, id) = value.rsplit_once(':').ok_or(CoreError::NotFound)?;
    let message_id = id.parse::<i32>().map_err(|_| CoreError::NotFound)?;
    if message_id <= 0 {
        return Err(CoreError::NotFound);
    }
    Ok(((scope != "root").then_some(scope), message_id))
}

fn redact_phone(phone: &str) -> String {
    let start = phone.chars().take(2).collect::<String>();
    let end = phone
        .chars()
        .rev()
        .take(2)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("{start}••••{end}")
}

fn map_io_error(_error: std::io::Error) -> CoreError {
    CoreError::Unavailable("Telegram file transfer failed".to_string())
}

fn map_auth_error(error: grammers_mtsender::InvocationError) -> CoreError {
    let value = error.to_string();
    let message = if value.contains("PHONE_NUMBER_INVALID") {
        "Telegram rejected the phone number"
    } else if value.contains("PHONE_NUMBER_BANNED") {
        "Telegram has banned this phone number"
    } else if value.contains("FLOOD") {
        "Telegram is rate-limiting authentication; try again later"
    } else if value.contains("API_ID_INVALID") {
        "the server Telegram API credentials are invalid"
    } else {
        "Telegram authentication failed"
    };
    CoreError::Unavailable(message.to_string())
}

fn map_network_error(_error: grammers_mtsender::InvocationError) -> CoreError {
    CoreError::Unavailable("Telegram request failed".to_string())
}
