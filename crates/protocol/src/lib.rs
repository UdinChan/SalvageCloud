//! Transport types shared by the native server and the WASM client.
//!
//! Account IDs returned here are informational only. The server always derives
//! authorization from the authenticated web session, never from these values.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub id: Uuid,
    pub telegram_user_id: String,
    pub display_name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionResponse {
    pub account: AccountInfo,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PhoneLoginRequest {
    pub phone: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginAttemptResponse {
    pub attempt_id: Uuid,
    pub phone_hint: String,
    pub code_length: Option<u8>,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyCodeRequest {
    pub attempt_id: Uuid,
    pub code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloudPasswordRequest {
    pub attempt_id: Uuid,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginOutcome {
    Authenticated { session: SessionResponse },
    PasswordRequired { password_hint: Option<String> },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Folder {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
    pub file_count: u64,
    #[serde(default)]
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateFolderRequest {
    pub name: String,
    pub parent_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RenameFolderRequest {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    Document,
    Image,
    Audio,
    Video,
    Archive,
    Other,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DriveFile {
    pub id: String,
    pub folder_id: Option<String>,
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub kind: FileKind,
    pub protected: bool,
    pub modified_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct FilePage {
    pub files: Vec<DriveFile>,
    pub next_cursor: Option<String>,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QrLoginAttemptResponse {
    pub attempt_id: Uuid,
    pub qr_svg: String,
    pub expires_in_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct QrPollResponse {
    pub complete: bool,
    pub qr_svg: Option<String>,
    pub session: Option<SessionResponse>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct BotTokenInfo {
    pub id: Uuid,
    pub label: String,
    pub bot_user_id: String,
    pub bot_username: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AddBotTokenRequest {
    pub label: String,
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Upload,
    Download,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransferStatus {
    Staging,
    Publishing,
    Ready,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Transfer {
    pub id: Uuid,
    pub direction: TransferDirection,
    pub status: TransferStatus,
    pub name: String,
    pub folder_id: Option<String>,
    pub size: u64,
    pub transferred: u64,
    pub mime_type: String,
    pub source_modified_ms: Option<i64>,
    #[serde(default)]
    pub source_file_id: Option<String>,
    #[serde(default)]
    pub protected: bool,
    #[serde(default)]
    pub bot_id: Option<Uuid>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateUploadRequest {
    pub name: String,
    pub folder_id: Option<String>,
    pub size: u64,
    pub mime_type: String,
    pub source_modified_ms: Option<i64>,
    pub prefix_sha256: Option<String>,
    /// True only for a client-produced TDENC2 envelope with a generic remote name.
    #[serde(default)]
    pub protected: bool,
    /// Optional per-account bot used only for an authorized channel/group publication.
    #[serde(default)]
    pub bot_id: Option<Uuid>,
    /// Select the least-loaded eligible bot at creation time.
    #[serde(default)]
    pub bot_auto: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UploadResponse {
    pub transfer: Transfer,
    pub next_offset: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompleteUploadResponse {
    pub transfer: Transfer,
    pub file: DriveFile,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DownloadResponse {
    pub transfer: Transfer,
    pub file: DriveFile,
    pub download_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreateShareRequest {
    /// Hours until the public link expires. Defaults to 24; 0 means never; maximum 168.
    pub expires_in_hours: Option<u16>,
    /// Optional precise expiry override. Maximum 604800 seconds (168 hours).
    pub expires_in_seconds: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Share {
    pub id: Uuid,
    pub file_id: String,
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CreatedShare {
    pub share: Share,
    /// Complete public URL path, returned only at creation.
    pub url_path: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ServerEvent {
    InventoryChanged {
        folder_id: Option<String>,
        revision: u64,
    },
    TransferUpdated {
        transfer: Transfer,
    },
    AccountRevoked,
    Heartbeat,
}
