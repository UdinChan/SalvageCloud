use std::{
    collections::BTreeMap,
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
};

use async_trait::async_trait;
use chrono::{TimeZone, Utc};
use dashmap::DashMap;
use salvage_protocol::{DriveFile, FileKind, Folder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{CoreError, Result};

use super::{
    PhoneAttempt, QrCodeAttempt, QrPoll, TelegramFactory, TelegramTransport, TelegramUser,
    TransportLogin, login_qr_svg,
};

const FIXTURE_CODE: &str = "12345";
const FIXTURE_PASSWORD: &str = "salvage-test-password";

#[derive(Clone, Default)]
pub struct FixtureFactory {
    accounts: Arc<DashMap<i64, Arc<FixtureState>>>,
}

impl FixtureFactory {
    pub fn new() -> Self {
        Self::default()
    }

    pub(crate) fn accounts(&self) -> Arc<DashMap<i64, Arc<FixtureState>>> {
        self.accounts.clone()
    }
}

pub(crate) struct FixtureState {
    pub(crate) user: TelegramUser,
    authenticated: AtomicBool,
    seeded: AtomicBool,
    pub(crate) folders: RwLock<BTreeMap<String, Folder>>,
    pub(crate) files: RwLock<BTreeMap<String, DriveFile>>,
    pub(crate) contents: RwLock<BTreeMap<String, Vec<u8>>>,
}

impl FixtureState {
    fn new(user: TelegramUser) -> Self {
        Self {
            user,
            authenticated: AtomicBool::new(false),
            seeded: AtomicBool::new(false),
            folders: RwLock::new(BTreeMap::new()),
            files: RwLock::new(BTreeMap::new()),
            contents: RwLock::new(BTreeMap::new()),
        }
    }

    fn seed(&self) {
        if self.seeded.swap(true, Ordering::SeqCst) {
            return;
        }
        let created_at = Utc
            .timestamp_opt(1_700_000_000, 0)
            .single()
            .expect("valid fixture timestamp");
        let documents = Folder {
            id: format!("documents-{}", self.user.id),
            parent_id: None,
            name: "Documents".to_string(),
            file_count: 1,
            active: false,
            created_at,
        };
        let media = Folder {
            id: format!("media-{}", self.user.id),
            parent_id: None,
            name: "Media".to_string(),
            file_count: 0,
            active: false,
            created_at,
        };
        let welcome_bytes = b"Welcome to your synthetic Salvage Cloud drive. This content is served by the controlled fixture.".to_vec();
        let reading_bytes = b"These are fixture-only reading notes.".to_vec();
        let welcome = DriveFile {
            id: format!("welcome-{}", self.user.id),
            folder_id: None,
            name: "Welcome to Salvage Cloud.txt".to_string(),
            mime_type: "text/plain".to_string(),
            size: welcome_bytes.len() as u64,
            kind: FileKind::Document,
            protected: false,
            modified_at: created_at,
        };
        let reading = DriveFile {
            id: format!("reading-{}", self.user.id),
            folder_id: Some(documents.id.clone()),
            name: "Reading list.txt".to_string(),
            mime_type: "text/plain".to_string(),
            size: reading_bytes.len() as u64,
            kind: FileKind::Document,
            protected: false,
            modified_at: created_at,
        };
        self.folders
            .write()
            .expect("fixture folders")
            .extend([(documents.id.clone(), documents), (media.id.clone(), media)]);
        self.files.write().expect("fixture files").extend([
            (welcome.id.clone(), welcome.clone()),
            (reading.id.clone(), reading.clone()),
        ]);
        self.contents.write().expect("fixture contents").extend([
            (welcome.id.clone(), welcome_bytes),
            (reading.id.clone(), reading_bytes),
        ]);
    }
}

struct FixtureTransport {
    state: Arc<FixtureState>,
    accounts: Arc<DashMap<i64, Arc<FixtureState>>>,
    code_verified: AtomicBool,
    requires_password: bool,
}

impl FixtureTransport {
    fn finish_authentication(&self) {
        self.accounts.insert(self.state.user.id, self.state.clone());
        self.state.authenticated.store(true, Ordering::SeqCst);
        self.state.seed();
    }

    fn require_authentication(&self) -> Result<()> {
        if self.state.authenticated.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized)
        }
    }
}

#[derive(Deserialize, Serialize)]
struct FixtureSession {
    telegram_user_id: i64,
    display_name: String,
}

#[async_trait]
impl TelegramFactory for FixtureFactory {
    async fn begin_phone_login(
        &self,
        phone: &str,
    ) -> Result<(Arc<dyn TelegramTransport>, PhoneAttempt)> {
        let digest = Sha256::digest(phone.as_bytes());
        let mut id_bytes = [0_u8; 8];
        id_bytes.copy_from_slice(&digest[..8]);
        let id = (i64::from_le_bytes(id_bytes) & 0x000f_ffff_ffff_ffff).max(1);
        let suffix = phone
            .chars()
            .rev()
            .take(2)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>();
        let user = TelegramUser {
            id,
            display_name: format!("Salvage Tester {suffix}"),
        };
        let transport = Arc::new(FixtureTransport {
            state: Arc::new(FixtureState::new(user)),
            accounts: self.accounts.clone(),
            code_verified: AtomicBool::new(false),
            requires_password: phone.ends_with("2222"),
        });
        Ok((
            transport,
            PhoneAttempt {
                phone_hint: format!("••••••{suffix}"),
                code_length: Some(5),
            },
        ))
    }

    async fn begin_qr_login(&self) -> Result<(Arc<dyn TelegramTransport>, QrCodeAttempt)> {
        let (transport, _) = self.begin_phone_login("qr-login").await?;
        Ok((
            transport,
            QrCodeAttempt {
                qr_svg: login_qr_svg(b"fixture-qr-token")?,
                expires_in_seconds: 30,
            },
        ))
    }

    async fn restore(&self, session: &[u8]) -> Result<Arc<dyn TelegramTransport>> {
        let saved: FixtureSession =
            serde_json::from_slice(session).map_err(|_| CoreError::Unauthorized)?;
        let user = TelegramUser {
            id: saved.telegram_user_id,
            display_name: saved.display_name,
        };
        let state = self
            .accounts
            .entry(user.id)
            .or_insert_with(|| Arc::new(FixtureState::new(user)))
            .clone();
        state.authenticated.store(true, Ordering::SeqCst);
        state.seed();
        Ok(Arc::new(FixtureTransport {
            state,
            accounts: self.accounts.clone(),
            code_verified: AtomicBool::new(true),
            requires_password: false,
        }))
    }
}

#[async_trait]
impl TelegramTransport for FixtureTransport {
    async fn verify_code(&self, code: &str) -> Result<TransportLogin> {
        if code != FIXTURE_CODE {
            return Err(CoreError::Unauthorized);
        }
        self.code_verified.store(true, Ordering::SeqCst);
        if self.requires_password {
            Ok(TransportLogin::PasswordRequired {
                password_hint: Some(
                    "Controlled fixture requires its test cloud password".to_string(),
                ),
            })
        } else {
            self.finish_authentication();
            Ok(TransportLogin::Authenticated)
        }
    }

    async fn verify_password(&self, password: &str) -> Result<()> {
        if !self.code_verified.load(Ordering::SeqCst) || password != FIXTURE_PASSWORD {
            return Err(CoreError::Unauthorized);
        }
        self.finish_authentication();
        Ok(())
    }

    async fn poll_qr_login(&self) -> Result<QrPoll> {
        self.finish_authentication();
        Ok(QrPoll::Ready(TransportLogin::Authenticated))
    }

    fn self_user(&self) -> Option<TelegramUser> {
        self.require_authentication()
            .ok()
            .map(|_| self.state.user.clone())
    }

    async fn export_session(&self) -> Result<Vec<u8>> {
        self.require_authentication()?;
        serde_json::to_vec(&FixtureSession {
            telegram_user_id: self.state.user.id,
            display_name: self.state.user.display_name.clone(),
        })
        .map_err(|error| CoreError::Internal(error.to_string()))
    }

    async fn logout(&self) -> Result<()> {
        self.state.authenticated.store(false, Ordering::SeqCst);
        Ok(())
    }

    async fn list_folders(&self, parent_id: Option<&str>) -> Result<Vec<Folder>> {
        self.require_authentication()?;
        let mut folders: Vec<_> = self
            .state
            .folders
            .read()
            .expect("fixture folders")
            .values()
            .filter(|folder| folder.parent_id.as_deref() == parent_id)
            .cloned()
            .collect();
        folders.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(folders)
    }

    async fn create_folder(&self, parent_id: Option<&str>, name: &str) -> Result<Folder> {
        self.require_authentication()?;
        let folder = Folder {
            id: Uuid::new_v4().to_string(),
            parent_id: parent_id.map(str::to_string),
            name: name.to_string(),
            file_count: 0,
            active: false,
            created_at: Utc::now(),
        };
        self.state
            .folders
            .write()
            .expect("fixture folders")
            .insert(folder.id.clone(), folder.clone());
        Ok(folder)
    }

    async fn rename_folder(&self, id: &str, name: &str) -> Result<Folder> {
        self.require_authentication()?;
        let mut folders = self.state.folders.write().expect("fixture folders");
        let folder = folders.get_mut(id).ok_or(CoreError::NotFound)?;
        folder.name = name.to_string();
        Ok(folder.clone())
    }

    async fn delete_folder(&self, id: &str) -> Result<()> {
        self.require_authentication()?;
        if self
            .state
            .folders
            .write()
            .expect("fixture folders")
            .remove(id)
            .is_none()
        {
            return Err(CoreError::NotFound);
        }
        self.state
            .files
            .write()
            .expect("fixture files")
            .retain(|_, file| file.folder_id.as_deref() != Some(id));
        Ok(())
    }

    async fn provision_bot(&self, _folder_id: &str, _bot_username: &str) -> Result<()> {
        self.require_authentication()
    }

    async fn list_files(
        &self,
        folder_id: Option<&str>,
        query: Option<&str>,
    ) -> Result<Vec<DriveFile>> {
        self.require_authentication()?;
        let needle = query.map(str::to_lowercase);
        let mut files: Vec<_> = self
            .state
            .files
            .read()
            .expect("fixture files")
            .values()
            .filter(|file| match (folder_id, query) {
                (None, None) => file.folder_id.is_none(),
                (None, Some(_)) => true,
                (Some(id), _) => file.folder_id.as_deref() == Some(id),
            })
            .filter(|file| {
                needle
                    .as_ref()
                    .is_none_or(|q| file.name.to_lowercase().contains(q))
            })
            .cloned()
            .collect();
        files.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(files)
    }

    async fn delete_file(&self, id: &str) -> Result<()> {
        self.require_authentication()?;
        if self
            .state
            .files
            .write()
            .expect("fixture files")
            .remove(id)
            .is_none()
        {
            return Err(CoreError::NotFound);
        }
        self.state
            .contents
            .write()
            .expect("fixture contents")
            .remove(id);
        Ok(())
    }

    async fn file_metadata(&self, id: &str) -> Result<DriveFile> {
        self.require_authentication()?;
        self.state
            .files
            .read()
            .expect("fixture files")
            .get(id)
            .cloned()
            .ok_or(CoreError::NotFound)
    }

    async fn publish_file(
        &self,
        source: &Path,
        folder_id: Option<&str>,
        name: &str,
        mime_type: &str,
    ) -> Result<DriveFile> {
        self.require_authentication()?;
        let bytes = tokio::fs::read(source).await?;
        let file = DriveFile {
            id: Uuid::new_v4().to_string(),
            folder_id: folder_id.map(str::to_string),
            name: name.to_string(),
            mime_type: mime_type.to_string(),
            size: bytes.len() as u64,
            kind: kind_for_mime(mime_type),
            protected: name.starts_with("TDENC2")
                || name.ends_with(".tdenc2")
                || name.ends_with(".tdenc"),
            modified_at: Utc::now(),
        };
        self.state
            .files
            .write()
            .expect("fixture files")
            .insert(file.id.clone(), file.clone());
        self.state
            .contents
            .write()
            .expect("fixture contents")
            .insert(file.id.clone(), bytes);
        if let Some(folder_id) = folder_id
            && let Some(folder) = self
                .state
                .folders
                .write()
                .expect("fixture folders")
                .get_mut(folder_id)
        {
            folder.file_count += 1;
        }
        Ok(file)
    }

    async fn download_file(&self, id: &str, destination: &Path) -> Result<DriveFile> {
        self.require_authentication()?;
        let file = self
            .state
            .files
            .read()
            .expect("fixture files")
            .get(id)
            .cloned()
            .ok_or(CoreError::NotFound)?;
        let bytes = self
            .state
            .contents
            .read()
            .expect("fixture contents")
            .get(id)
            .cloned()
            .ok_or(CoreError::NotFound)?;
        tokio::fs::write(destination, bytes).await?;
        Ok(file)
    }
}

fn kind_for_mime(mime_type: &str) -> FileKind {
    if mime_type.starts_with("image/") {
        FileKind::Image
    } else if mime_type.starts_with("video/") {
        FileKind::Video
    } else if mime_type.starts_with("audio/") {
        FileKind::Audio
    } else if mime_type.starts_with("text/") || mime_type == "application/pdf" {
        FileKind::Document
    } else if mime_type.contains("zip") || mime_type.contains("compressed") {
        FileKind::Archive
    } else {
        FileKind::Other
    }
}
