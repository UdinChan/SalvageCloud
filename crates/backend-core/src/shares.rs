use std::{path::PathBuf, sync::Arc};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngCore;
use salvage_protocol::{CreatedShare, Share, Transfer, TransferDirection, TransferStatus};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    CoreError, Result,
    accounts::{AccountGuard, AccountRegistry},
    store::{ServiceStore, ShareRecord},
    transfers,
};

pub struct ShareService {
    store: ServiceStore,
    registry: Arc<AccountRegistry>,
}

pub struct PublicContent {
    pub transfer: Transfer,
    pub path: PathBuf,
}

impl ShareService {
    pub fn new(store: ServiceStore, registry: Arc<AccountRegistry>) -> Self {
        Self { store, registry }
    }

    pub async fn create(
        &self,
        guard: &AccountGuard,
        file_id: &str,
        expires_in_hours: Option<u16>,
        expires_in_seconds: Option<u32>,
    ) -> Result<CreatedShare> {
        guard.validate()?;
        let expiry_seconds = match expires_in_seconds {
            Some(seconds) if (1..=604_800).contains(&seconds) => Some(i64::from(seconds)),
            Some(_) => {
                return Err(CoreError::InvalidInput(
                    "share expiry must be between 1 second and 168 hours".to_string(),
                ));
            }
            None => match expires_in_hours.unwrap_or(24) {
                0 => None,
                hours @ 1..=168 => Some(i64::from(hours) * 3_600),
                _ => {
                    return Err(CoreError::InvalidInput(
                        "share expiry must be between 1 and 168 hours, or 0 for no expiry"
                            .to_string(),
                    ));
                }
            },
        };
        let context = guard.context();
        let file = context.transport().await?.file_metadata(file_id).await?;
        if file.protected {
            return Err(CoreError::InvalidInput(
                "encrypted files cannot be shared".to_string(),
            ));
        }
        let download = transfers::prepare_download(guard, file_id).await?;
        let token = random_token();
        let now = Utc::now();
        let record = ShareRecord {
            id: Uuid::new_v4(),
            token_hash: token_hash(&token),
            account_id: context.info().id,
            file_id: file.id,
            transfer_id: download.transfer.id,
            name: file.name,
            mime_type: file.mime_type,
            size: file.size,
            created_at: now,
            expires_at: expiry_seconds.map(|seconds| now + chrono::Duration::seconds(seconds)),
            revoked_at: None,
        };
        if let Err(error) = self.store.insert_share(&record).await {
            let _ = tokio::fs::remove_file(context.transfer_path(record.transfer_id)).await;
            return Err(error);
        }
        Ok(CreatedShare {
            share: record.to_protocol(),
            url_path: format!("/s/{token}"),
        })
    }

    pub async fn list(&self, guard: &AccountGuard, file_id: &str) -> Result<Vec<Share>> {
        guard.validate()?;
        let account_id = guard.context().info().id;
        let records = self.store.shares_for_file(account_id, file_id).await?;
        Ok(records.iter().map(ShareRecord::to_protocol).collect())
    }

    pub async fn revoke(&self, guard: &AccountGuard, id: Uuid) -> Result<Share> {
        guard.validate()?;
        let context = guard.context();
        let record = self
            .store
            .revoke_share(id, context.info().id, Utc::now())
            .await?
            .ok_or(CoreError::NotFound)?;
        let _ = tokio::fs::remove_file(context.transfer_path(record.transfer_id)).await;
        Ok(record.to_protocol())
    }

    pub async fn cleanup_expired(&self) -> Result<usize> {
        let expired = self.store.expired_shares(Utc::now()).await?;
        let mut removed = 0;
        for record in expired {
            let Some(account) = self.store.account_by_id(record.account_id).await? else {
                continue;
            };
            let context = self.registry.open_workspace(account.into()).await?;
            if tokio::fs::remove_file(context.transfer_path(record.transfer_id))
                .await
                .is_ok()
            {
                removed += 1;
            }
        }
        Ok(removed)
    }

    pub async fn public_content(&self, token: &str) -> Result<PublicContent> {
        if token.len() != 43
            || !token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(CoreError::NotFound);
        }
        let record = self
            .store
            .share_by_token_hash(&token_hash(token))
            .await?
            .ok_or(CoreError::NotFound)?;
        if record.revoked_at.is_some()
            || record.expires_at.is_some_and(|expiry| expiry <= Utc::now())
        {
            return Err(CoreError::NotFound);
        }
        let account = self
            .store
            .account_by_id(record.account_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        let context = self.registry.open_workspace(account.into()).await?;
        let transfer = context
            .workspace()
            .transfer(record.transfer_id)
            .await?
            .ok_or(CoreError::NotFound)?;
        if transfer.direction != TransferDirection::Download
            || !matches!(
                transfer.status,
                TransferStatus::Ready | TransferStatus::Completed
            )
            || transfer.name != record.name
            || transfer.mime_type != record.mime_type
            || transfer.size != record.size
            || transfer.transferred != record.size
        {
            return Err(CoreError::NotFound);
        }
        let path = context.transfer_path(record.transfer_id);
        if tokio::fs::metadata(&path).await?.len() != record.size {
            return Err(CoreError::NotFound);
        }
        Ok(PublicContent { transfer, path })
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
