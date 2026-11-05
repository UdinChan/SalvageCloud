#[cfg(feature = "e2e-fixture")]
pub mod bot_fixture;
pub mod bots;
#[cfg(feature = "e2e-fixture")]
pub mod fixture;
pub mod live;
pub mod persisted_session;
pub mod resumable;

use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use salvage_protocol::{DriveFile, Folder};

use crate::{CoreError, Result};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TelegramUser {
    pub id: i64,
    pub display_name: String,
}

#[derive(Clone, Debug)]
pub struct PhoneAttempt {
    pub phone_hint: String,
    pub code_length: Option<u8>,
}

#[derive(Clone, Debug)]
pub enum TransportLogin {
    Authenticated,
    PasswordRequired { password_hint: Option<String> },
}

#[derive(Clone, Debug)]
pub struct QrCodeAttempt {
    pub qr_svg: String,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Debug)]
pub enum QrPoll {
    Pending { qr_svg: Option<String> },
    Ready(TransportLogin),
}

#[async_trait]
pub trait TelegramTransport: Send + Sync {
    async fn verify_code(&self, code: &str) -> Result<TransportLogin>;
    async fn verify_password(&self, password: &str) -> Result<()>;
    async fn poll_qr_login(&self) -> Result<QrPoll> {
        Err(crate::CoreError::InvalidInput(
            "QR login is not available for this login attempt".to_string(),
        ))
    }
    fn self_user(&self) -> Option<TelegramUser>;
    async fn export_session(&self) -> Result<Vec<u8>>;
    fn bind_persistent_session(&self, _account_dir: &Path) -> Result<()> {
        Ok(())
    }
    async fn logout(&self) -> Result<()>;

    async fn list_folders(&self, parent_id: Option<&str>) -> Result<Vec<Folder>>;
    async fn create_folder(&self, parent_id: Option<&str>, name: &str) -> Result<Folder>;
    async fn rename_folder(&self, id: &str, name: &str) -> Result<Folder>;
    async fn delete_folder(&self, id: &str) -> Result<()>;
    async fn provision_bot(&self, _folder_id: &str, _bot_username: &str) -> Result<()> {
        Err(crate::CoreError::InvalidInput(
            "automatic bot provisioning is not supported by this transport".to_string(),
        ))
    }
    async fn list_files(
        &self,
        folder_id: Option<&str>,
        query: Option<&str>,
    ) -> Result<Vec<DriveFile>>;
    async fn delete_file(&self, id: &str) -> Result<()>;
    async fn file_metadata(&self, id: &str) -> Result<DriveFile>;
    async fn publish_file(
        &self,
        source: &Path,
        folder_id: Option<&str>,
        name: &str,
        mime_type: &str,
    ) -> Result<DriveFile>;
    async fn download_file(&self, id: &str, destination: &Path) -> Result<DriveFile>;
}

#[async_trait]
pub trait TelegramFactory: Send + Sync {
    async fn begin_phone_login(
        &self,
        phone: &str,
    ) -> Result<(Arc<dyn TelegramTransport>, PhoneAttempt)>;
    async fn begin_qr_login(&self) -> Result<(Arc<dyn TelegramTransport>, QrCodeAttempt)> {
        Err(crate::CoreError::InvalidInput(
            "QR login is not supported by this Telegram transport".to_string(),
        ))
    }
    async fn restore(&self, session: &[u8]) -> Result<Arc<dyn TelegramTransport>>;
}

pub fn login_qr_svg(token: &[u8]) -> Result<String> {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use qrcode::render::svg;

    let url = format!("tg://login?token={}", URL_SAFE_NO_PAD.encode(token));
    let code = qrcode::QrCode::new(url)
        .map_err(|error| CoreError::Internal(format!("could not create login QR code: {error}")))?;
    Ok(code
        .render()
        .min_dimensions(256, 256)
        .dark_color(svg::Color("#123c34"))
        .light_color(svg::Color("#ffffff"))
        .build())
}
