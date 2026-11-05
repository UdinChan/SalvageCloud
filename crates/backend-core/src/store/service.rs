use std::{path::Path, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use salvage_protocol::AccountInfo;
use sqlite::{Connection, State, Value};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{CoreError, Result};

#[derive(Clone)]
pub struct ServiceStore {
    connection: Arc<Mutex<Connection>>,
}

#[derive(Clone, Debug)]
pub struct AccountRecord {
    pub id: Uuid,
    pub telegram_user_id: i64,
    pub display_name: String,
}

impl From<AccountRecord> for AccountInfo {
    fn from(value: AccountRecord) -> Self {
        Self {
            id: value.id,
            telegram_user_id: value.telegram_user_id.to_string(),
            display_name: value.display_name,
        }
    }
}

#[derive(Clone, Debug)]
pub struct WebSessionRecord {
    pub token_hash: String,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
    pub account_id: Uuid,
    pub telegram_user_id: i64,
    pub display_name: String,
}

impl WebSessionRecord {
    pub fn account(&self) -> AccountInfo {
        AccountInfo {
            id: self.account_id,
            telegram_user_id: self.telegram_user_id.to_string(),
            display_name: self.display_name.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ShareRecord {
    pub id: Uuid,
    pub token_hash: String,
    pub account_id: Uuid,
    pub file_id: String,
    pub transfer_id: Uuid,
    pub name: String,
    pub mime_type: String,
    pub size: u64,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ShareRecord {
    pub fn to_protocol(&self) -> salvage_protocol::Share {
        salvage_protocol::Share {
            id: self.id,
            file_id: self.file_id.clone(),
            name: self.name.clone(),
            mime_type: self.mime_type.clone(),
            size: self.size,
            created_at: self.created_at,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
        }
    }
}

impl ServiceStore {
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let connection = Connection::open(path)?;
        connection.execute(
            "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;",
        )?;
        connection.execute(
            "CREATE TABLE IF NOT EXISTS accounts (
                id TEXT PRIMARY KEY,
                telegram_user_id INTEGER NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL
            ) STRICT;
            CREATE TABLE IF NOT EXISTS web_sessions (
                token_hash TEXT PRIMARY KEY,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            ) STRICT;
            CREATE INDEX IF NOT EXISTS web_sessions_account ON web_sessions(account_id);
            CREATE INDEX IF NOT EXISTS web_sessions_expiry ON web_sessions(expires_at);
            CREATE TABLE IF NOT EXISTS public_shares (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                file_id TEXT NOT NULL,
                transfer_id TEXT NOT NULL,
                name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT
            ) STRICT;
            CREATE INDEX IF NOT EXISTS public_shares_owner ON public_shares(account_id, file_id);
            CREATE INDEX IF NOT EXISTS public_shares_expiry ON public_shares(expires_at);",
        )?;
        migrate_share_expiry_nullability(&connection)?;
        Ok(Self {
            connection: Arc::new(Mutex::new(connection)),
        })
    }

    pub async fn find_or_create_account(
        &self,
        telegram_user_id: i64,
        display_name: &str,
    ) -> Result<AccountRecord> {
        let connection = self.connection.lock().await;
        let id = Uuid::new_v4();
        execute_with(&connection,
            "INSERT INTO accounts (id, telegram_user_id, display_name, created_at) VALUES (?, ?, ?, ?)
             ON CONFLICT(telegram_user_id) DO UPDATE SET display_name = excluded.display_name",
            &[
                Value::String(id.to_string()),
                Value::Integer(telegram_user_id),
                Value::String(display_name.to_string()),
                Value::String(Utc::now().to_rfc3339()),
            ],
        )?;
        let mut statement = connection.prepare(
            "SELECT id, telegram_user_id, display_name FROM accounts WHERE telegram_user_id = ?",
        )?;
        statement.bind((1, telegram_user_id))?;
        if statement.next()? != State::Row {
            return Err(CoreError::Internal(
                "account could not be persisted".to_string(),
            ));
        }
        Ok(AccountRecord {
            id: parse_uuid(&statement.read::<String, _>(0)?)?,
            telegram_user_id: statement.read::<i64, _>(1)?,
            display_name: statement.read::<String, _>(2)?,
        })
    }

    pub async fn create_web_session(
        &self,
        account_id: Uuid,
        token_hash: &str,
        csrf_token: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "INSERT INTO web_sessions (token_hash, account_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
            &[
                Value::String(token_hash.to_string()),
                Value::String(account_id.to_string()),
                Value::String(csrf_token.to_string()),
                Value::String(expires_at.to_rfc3339()),
                Value::String(Utc::now().to_rfc3339()),
            ],
        )?;
        Ok(())
    }

    pub async fn find_web_session(&self, token_hash: &str) -> Result<Option<WebSessionRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT s.token_hash, s.csrf_token, s.expires_at, a.id, a.telegram_user_id, a.display_name
             FROM web_sessions s JOIN accounts a ON a.id = s.account_id WHERE s.token_hash = ?",
        )?;
        statement.bind((1, token_hash))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        Ok(Some(WebSessionRecord {
            token_hash: statement.read::<String, _>(0)?,
            csrf_token: statement.read::<String, _>(1)?,
            expires_at: parse_time(&statement.read::<String, _>(2)?)?,
            account_id: parse_uuid(&statement.read::<String, _>(3)?)?,
            telegram_user_id: statement.read::<i64, _>(4)?,
            display_name: statement.read::<String, _>(5)?,
        }))
    }

    pub async fn revoke_web_sessions(&self, account_id: Uuid) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "DELETE FROM web_sessions WHERE account_id = ?",
            &[Value::String(account_id.to_string())],
        )?;
        Ok(())
    }

    pub async fn account_by_id(&self, account_id: Uuid) -> Result<Option<AccountRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection
            .prepare("SELECT id, telegram_user_id, display_name FROM accounts WHERE id = ?")?;
        let account_id = account_id.to_string();
        statement.bind((1, account_id.as_str()))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        Ok(Some(AccountRecord {
            id: parse_uuid(&statement.read::<String, _>(0)?)?,
            telegram_user_id: statement.read::<i64, _>(1)?,
            display_name: statement.read::<String, _>(2)?,
        }))
    }

    pub async fn insert_share(&self, share: &ShareRecord) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(&connection,
            "INSERT INTO public_shares (id, token_hash, account_id, file_id, transfer_id, name, mime_type, size, created_at, expires_at, revoked_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            &[
                Value::String(share.id.to_string()),
                Value::String(share.token_hash.clone()),
                Value::String(share.account_id.to_string()),
                Value::String(share.file_id.clone()),
                Value::String(share.transfer_id.to_string()),
                Value::String(share.name.clone()),
                Value::String(share.mime_type.clone()),
                Value::Integer(share.size as i64),
                Value::String(share.created_at.to_rfc3339()),
                share.expires_at.map(|value| Value::String(value.to_rfc3339())).unwrap_or(Value::Null),
                share.revoked_at.map(|value| Value::String(value.to_rfc3339())).unwrap_or(Value::Null),
            ],
        )?;
        Ok(())
    }

    pub async fn share_by_id(&self, id: Uuid, account_id: Uuid) -> Result<Option<ShareRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT id, token_hash, account_id, file_id, transfer_id, name, mime_type, size, created_at, expires_at, revoked_at
             FROM public_shares WHERE id = ? AND account_id = ?",
        )?;
        let id = id.to_string();
        let account_id = account_id.to_string();
        statement.bind((1, id.as_str()))?;
        statement.bind((2, account_id.as_str()))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        Ok(Some(share_from_row(&statement)?))
    }

    pub async fn shares_for_file(
        &self,
        account_id: Uuid,
        file_id: &str,
    ) -> Result<Vec<ShareRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT id, token_hash, account_id, file_id, transfer_id, name, mime_type, size, created_at, expires_at, revoked_at
             FROM public_shares WHERE account_id = ? AND file_id = ? ORDER BY created_at DESC",
        )?;
        let account_id = account_id.to_string();
        statement.bind((1, account_id.as_str()))?;
        statement.bind((2, file_id))?;
        let mut shares = Vec::new();
        while statement.next()? == State::Row {
            shares.push(share_from_row(&statement)?);
        }
        Ok(shares)
    }

    pub async fn expired_shares(&self, now: DateTime<Utc>) -> Result<Vec<ShareRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT id, token_hash, account_id, file_id, transfer_id, name, mime_type, size, created_at, expires_at, revoked_at
             FROM public_shares WHERE expires_at IS NOT NULL AND expires_at <= ?",
        )?;
        let now = now.to_rfc3339();
        statement.bind((1, now.as_str()))?;
        let mut shares = Vec::new();
        while statement.next()? == State::Row {
            shares.push(share_from_row(&statement)?);
        }
        Ok(shares)
    }

    pub async fn share_by_token_hash(&self, token_hash: &str) -> Result<Option<ShareRecord>> {
        let connection = self.connection.lock().await;
        let mut statement = connection.prepare(
            "SELECT id, token_hash, account_id, file_id, transfer_id, name, mime_type, size, created_at, expires_at, revoked_at
             FROM public_shares WHERE token_hash = ?",
        )?;
        statement.bind((1, token_hash))?;
        if statement.next()? == State::Done {
            return Ok(None);
        }
        Ok(Some(share_from_row(&statement)?))
    }

    pub async fn revoke_share(
        &self,
        id: Uuid,
        account_id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<Option<ShareRecord>> {
        {
            let connection = self.connection.lock().await;
            execute_with(
                &connection,
                "UPDATE public_shares SET revoked_at = ? WHERE id = ? AND account_id = ? AND revoked_at IS NULL",
                &[
                    Value::String(revoked_at.to_rfc3339()),
                    Value::String(id.to_string()),
                    Value::String(account_id.to_string()),
                ],
            )?;
        }
        self.share_by_id(id, account_id).await
    }

    pub async fn delete_expired_sessions(&self) -> Result<()> {
        let connection = self.connection.lock().await;
        execute_with(
            &connection,
            "DELETE FROM web_sessions WHERE expires_at <= ?",
            &[Value::String(Utc::now().to_rfc3339())],
        )?;
        Ok(())
    }
}

fn migrate_share_expiry_nullability(connection: &Connection) -> Result<()> {
    let mut statement = connection.prepare("PRAGMA table_info(public_shares)")?;
    let mut required = false;
    while statement.next()? == State::Row {
        if statement.read::<String, _>(1)? == "expires_at" && statement.read::<i64, _>(3)? != 0 {
            required = true;
        }
    }
    if !required {
        return Ok(());
    }
    connection.execute("BEGIN IMMEDIATE")?;
    let result: Result<()> = (|| {
        connection.execute("ALTER TABLE public_shares RENAME TO public_shares_expiry_v1")?;
        connection.execute(
            "CREATE TABLE public_shares (
                id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
                file_id TEXT NOT NULL,
                transfer_id TEXT NOT NULL,
                name TEXT NOT NULL,
                mime_type TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT
            ) STRICT;
            INSERT INTO public_shares SELECT * FROM public_shares_expiry_v1;
            DROP TABLE public_shares_expiry_v1;
            CREATE INDEX public_shares_owner ON public_shares(account_id, file_id);
            CREATE INDEX public_shares_expiry ON public_shares(expires_at);",
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

fn execute_with(connection: &Connection, sql: &str, values: &[Value]) -> Result<()> {
    let mut statement = connection.prepare(sql)?;
    for (index, value) in values.iter().enumerate() {
        statement.bind((index + 1, value.clone()))?;
    }
    statement.next()?;
    Ok(())
}

fn share_from_row(statement: &sqlite::Statement) -> Result<ShareRecord> {
    Ok(ShareRecord {
        id: parse_uuid(&statement.read::<String, _>(0)?)?,
        token_hash: statement.read::<String, _>(1)?,
        account_id: parse_uuid(&statement.read::<String, _>(2)?)?,
        file_id: statement.read::<String, _>(3)?,
        transfer_id: parse_uuid(&statement.read::<String, _>(4)?)?,
        name: statement.read::<String, _>(5)?,
        mime_type: statement.read::<String, _>(6)?,
        size: statement.read::<i64, _>(7)?.max(0) as u64,
        created_at: parse_time(&statement.read::<String, _>(8)?)?,
        expires_at: statement
            .read::<Option<String>, _>(9)?
            .map(|value| parse_time(&value))
            .transpose()?,
        revoked_at: statement
            .read::<Option<String>, _>(10)?
            .map(|value| parse_time(&value))
            .transpose()?,
    })
}

fn parse_uuid(value: &str) -> Result<Uuid> {
    Uuid::from_str(value)
        .map_err(|_| CoreError::Internal("stored account ID is invalid".to_string()))
}

fn parse_time(value: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| CoreError::Internal("stored session expiry is invalid".to_string()))
}
