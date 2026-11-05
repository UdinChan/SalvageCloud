use std::{path::Path, sync::Arc};

use salvage_protocol::{
    BotTokenInfo, DriveFile, FilePage, Folder, Transfer, TransferDirection, TransferStatus,
};
use serde::{Deserialize, Serialize};
use sqlite::{Connection, State, Value};
use tokio::sync::Mutex;

use crate::{CoreError, Result};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StoredBotToken {
    pub info: BotTokenInfo,
    pub token_envelope: String,
    pub session_envelope: String,
}

#[derive(Clone)]
pub struct WorkspaceStore {
    connection: Arc<Mutex<Connection>>,
}

impl WorkspaceStore {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let connection = Connection::open(path)?;
        connection.execute(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;",
        )?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS folders (
                id TEXT PRIMARY KEY,
                parent_id TEXT,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS folders_parent ON folders(parent_id);
            CREATE TABLE IF NOT EXISTS files (
                id TEXT PRIMARY KEY,
                folder_id TEXT,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS files_folder ON files(folder_id);
            CREATE TABLE IF NOT EXISTS transfers (
                id TEXT PRIMARY KEY,
                direction TEXT NOT NULL,
                status TEXT NOT NULL,
                name TEXT NOT NULL,
                folder_id TEXT,
                size INTEGER NOT NULL,
                transferred INTEGER NOT NULL,
                mime_type TEXT NOT NULL,
                source_modified_ms INTEGER,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS transfers_updated ON transfers(updated_at);
            CREATE TABLE IF NOT EXISTS bot_tokens (
                id TEXT PRIMARY KEY,
                bot_user_id TEXT NOT NULL UNIQUE,
                payload TEXT NOT NULL,
                created_at TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            ) STRICT;",
        )?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub async fn cache_folder(&self, folder: &Folder) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(&connection,
            "INSERT INTO folders (id, parent_id, payload, updated_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET parent_id=excluded.parent_id, payload=excluded.payload, updated_at=excluded.updated_at",
            &[
                Value::String(folder.id.clone()),
                optional_string(folder.parent_id.as_deref()),
                Value::String(json(folder)?),
                Value::String(chrono::Utc::now().to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub async fn cache_files(&self, files: &[DriveFile]) -> Result<()> {
        let connection = self.connection.lock().await;
        connection.execute("BEGIN IMMEDIATE")?;
        let result: Result<()> = (|| {
            for file in files {
                execute_with(&connection,
                    "INSERT INTO files (id, folder_id, payload, updated_at) VALUES (?, ?, ?, ?)
                     ON CONFLICT(id) DO UPDATE SET folder_id=excluded.folder_id, payload=excluded.payload, updated_at=excluded.updated_at",
                    &[
                        Value::String(file.id.clone()),
                        optional_string(file.folder_id.as_deref()),
                        Value::String(json(file)?),
                        Value::String(chrono::Utc::now().to_rfc3339()),
                    ],
                )?;
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                connection.execute("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = connection.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub async fn remove_folder(&self, id: &str) -> Result<()> {
        let connection = self.connection.lock().await;
        connection.execute("BEGIN IMMEDIATE")?;
        let result: Result<()> = (|| {
            execute_with(
                &connection,
                "DELETE FROM folders WHERE id = ?",
                &[Value::String(id.to_string())],
            )?;
            execute_with(
                &connection,
                "DELETE FROM files WHERE folder_id = ?",
                &[Value::String(id.to_string())],
            )?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                connection.execute("COMMIT")?;
                Ok(())
            }
            Err(error) => {
                let _ = connection.execute("ROLLBACK");
                Err(error)
            }
        }
    }

    pub async fn remove_file(&self, id: &str) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "DELETE FROM files WHERE id = ?",
            &[Value::String(id.to_string())],
        )?;
        Ok(())
    }

    pub async fn cached_file(&self, id: &str) -> Result<Option<DriveFile>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare("SELECT payload FROM files WHERE id = ?")?;
        statement.bind((1, id))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        let file = serde_json::from_str(&statement.read::<String, _>(0)?)
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        Ok(Some(file))
    }

    pub async fn cached_files(
        &self,
        folder_id: Option<&str>,
        query: Option<&str>,
    ) -> Result<FilePage> {
        let connection = self.connection.lock().await;
        let sql = match (folder_id, query) {
            (None, None) => {
                "SELECT payload FROM files WHERE folder_id IS NULL ORDER BY updated_at DESC"
            }
            (None, Some(_)) => "SELECT payload FROM files ORDER BY updated_at DESC",
            (Some(_), _) => {
                "SELECT payload FROM files WHERE folder_id = ? ORDER BY updated_at DESC"
            }
        };
        let mut statement = connection.prepare(sql)?;
        if let Some(id) = folder_id {
            statement.bind((1, id))?;
        }
        let needle = query.map(str::to_lowercase);
        let mut files = Vec::new();
        while statement.next()? == State::Row {
            let file: DriveFile = serde_json::from_str(&statement.read::<String, _>(0)?)
                .map_err(|error| CoreError::Internal(error.to_string()))?;
            if needle
                .as_ref()
                .is_none_or(|needle| file.name.to_lowercase().contains(needle))
            {
                files.push(file);
            }
        }
        Ok(FilePage {
            files,
            next_cursor: None,
            complete: true,
        })
    }
    pub async fn active_channel(&self) -> Result<Option<String>> {
        let connection = self.connection.lock().await;
        let mut statement =
            connection.prepare("SELECT value FROM settings WHERE key = 'active_channel'")?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        Ok(Some(statement.read::<String, _>(0)?))
    }

    pub async fn set_active_channel(&self, id: &str) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "INSERT INTO settings (key, value) VALUES ('active_channel', ?)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            &[Value::String(id.to_string())],
        )?;
        Ok(())
    }

    pub async fn count_channel_files(&self, id: &str) -> Result<u64> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare("SELECT COUNT(*) FROM files WHERE folder_id = ?")?;
        statement.bind((1, id))?;
        if statement.next()? == State::Done {
            return Ok(0);
        }
        Ok(statement.read::<i64, _>(0)?.max(0) as u64)
    }

    pub async fn put_bot_token(&self, record: &StoredBotToken) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "INSERT INTO bot_tokens (id, bot_user_id, payload, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET payload=excluded.payload",
            &[
                Value::String(record.info.id.to_string()),
                Value::String(record.info.bot_user_id.clone()),
                Value::String(json(record)?),
                Value::String(record.info.created_at.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub async fn update_bot_session(&self, id: uuid::Uuid, envelope: String) -> Result<()> {
        let mut record = self.bot_token(id).await?.ok_or(CoreError::NotFound)?;
        record.session_envelope = envelope;
        self.put_bot_token(&record).await
    }

    pub async fn bot_token(&self, id: uuid::Uuid) -> Result<Option<StoredBotToken>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare("SELECT payload FROM bot_tokens WHERE id = ?")?;
        statement.bind((1, id.to_string().as_str()))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        let record = serde_json::from_str(&statement.read::<String, _>(0)?)
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        Ok(Some(record))
    }

    pub async fn bot_tokens(&self) -> Result<Vec<StoredBotToken>> {
        let connection = self.connection.lock().await;
        let mut statement =
            connection.prepare("SELECT payload FROM bot_tokens ORDER BY created_at DESC")?;
        let mut records = Vec::new();
        while statement.next()? == State::Row {
            records.push(
                serde_json::from_str(&statement.read::<String, _>(0)?)
                    .map_err(|error| CoreError::Internal(error.to_string()))?,
            );
        }
        Ok(records)
    }

    pub async fn delete_bot_token(&self, id: uuid::Uuid) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "DELETE FROM bot_tokens WHERE id = ?",
            &[Value::String(id.to_string())],
        )?;
        Ok(())
    }

    pub async fn put_transfer(&self, transfer: &Transfer) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(&connection,
            "INSERT INTO transfers (id, direction, status, name, folder_id, size, transferred, mime_type, source_modified_ms, payload, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET status=excluded.status, transferred=excluded.transferred, payload=excluded.payload, updated_at=excluded.updated_at",
            &[
                Value::String(transfer.id.to_string()),
                Value::String(direction_name(&transfer.direction).to_string()),
                Value::String(status_name(&transfer.status).to_string()),
                Value::String(transfer.name.clone()),
                optional_string(transfer.folder_id.as_deref()),
                Value::Integer(transfer.size as i64),
                Value::Integer(transfer.transferred as i64),
                Value::String(transfer.mime_type.clone()),
                transfer.source_modified_ms.map(Value::Integer).unwrap_or(Value::Null),
                Value::String(json(transfer)?),
                Value::String(transfer.created_at.to_rfc3339()),
                Value::String(transfer.updated_at.to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub async fn transfer(&self, id: uuid::Uuid) -> Result<Option<Transfer>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare("SELECT payload FROM transfers WHERE id = ?")?;
        let id = id.to_string();
        statement.bind((1, id.as_str()))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        let transfer = serde_json::from_str(&statement.read::<String, _>(0)?)
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        Ok(Some(transfer))
    }

    pub async fn transfers(&self) -> Result<Vec<Transfer>> {
        let connection = self.connection.lock().await;
        let mut statement =
            connection.prepare("SELECT payload FROM transfers ORDER BY updated_at DESC")?;
        let mut transfers = Vec::new();
        while statement.next()? == State::Row {
            transfers.push(
                serde_json::from_str(&statement.read::<String, _>(0)?)
                    .map_err(|error| CoreError::Internal(error.to_string()))?,
            );
        }
        Ok(transfers)
    }

    pub async fn resumable_upload(
        &self,
        request: &salvage_protocol::CreateUploadRequest,
    ) -> Result<Option<Transfer>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT payload FROM transfers
             WHERE direction = 'upload' AND status IN ('staging', 'failed')
               AND name = ? AND folder_id IS ? AND size = ? AND source_modified_ms IS ?
             ORDER BY updated_at DESC LIMIT 1",
        )?;
        statement.bind((1, request.name.as_str()))?;
        statement.bind((2, optional_string(request.folder_id.as_deref())))?;
        statement.bind((3, request.size as i64))?;
        statement.bind((
            4,
            request
                .source_modified_ms
                .map(Value::Integer)
                .unwrap_or(Value::Null),
        ))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        let transfer = serde_json::from_str(&statement.read::<String, _>(0)?)
            .map_err(|error| CoreError::Internal(error.to_string()))?;
        Ok(Some(transfer))
    }
}

fn direction_name(direction: &TransferDirection) -> &'static str {
    match direction {
        TransferDirection::Upload => "upload",
        TransferDirection::Download => "download",
    }
}

fn status_name(status: &TransferStatus) -> &'static str {
    match status {
        TransferStatus::Staging => "staging",
        TransferStatus::Publishing => "publishing",
        TransferStatus::Ready => "ready",
        TransferStatus::Completed => "completed",
        TransferStatus::Failed => "failed",
        TransferStatus::Cancelled => "cancelled",
    }
}
fn execute_with(connection: &Connection, sql: &str, values: &[Value]) -> Result<()> {
    let mut statement = connection.prepare(sql)?;
    for (index, value) in values.iter().enumerate() {
        statement.bind((index + 1, value.clone()))?;
    }
    statement.next()?;
    Ok(())
}

fn json<T: serde::Serialize>(value: &T) -> Result<String> {
    serde_json::to_string(value).map_err(|error| CoreError::Internal(error.to_string()))
}

fn optional_string(value: Option<&str>) -> Value {
    value
        .map(|value| Value::String(value.to_string()))
        .unwrap_or(Value::Null)
}
