use std::path::{Path, PathBuf};

use chrono::Utc;
use salvage_protocol::{
    CompleteUploadResponse, CreateUploadRequest, DownloadResponse, ServerEvent, Transfer,
    TransferDirection, TransferStatus, UploadResponse,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{CoreError, Result, accounts::AccountGuard};

pub const MAX_TRANSFER_BYTES: u64 = 2_000_000_000;
pub const MAX_BROWSER_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

pub async fn create_upload(
    guard: &AccountGuard,
    mut request: CreateUploadRequest,
) -> Result<UploadResponse> {
    guard.validate()?;
    validate_upload(&request)?;
    let context = guard.context();
    let active_channel = context.workspace().active_channel().await?;
    if request.folder_id == active_channel
        && active_channel.is_some()
        && context.channel_part_limit() > 0
        && context
            .workspace()
            .count_channel_files(active_channel.as_deref().unwrap_or_default())
            .await?
            >= context.channel_part_limit()
    {
        let folder = crate::drive::create_folder(
            guard,
            salvage_protocol::CreateFolderRequest {
                name: format!("salvage_{}", Utc::now().format("%Y%m%d_%H%M%S")),
                parent_id: None,
            },
        )
        .await?;
        context.workspace().set_active_channel(&folder.id).await?;
        request.folder_id = Some(folder.id);
    }
    if request.bot_auto {
        if request.bot_id.is_some() {
            return Err(CoreError::InvalidInput(
                "choose either automatic bot selection or an explicit bot".to_string(),
            ));
        }
        request.bot_id = Some(
            context
                .bots()
                .select_upload_bot(request.folder_id.as_deref())
                .await?,
        );
    }
    if let Some(bot_id) = request.bot_id {
        context
            .bots()
            .validate_upload(bot_id, request.folder_id.as_deref())
            .await?;
    }
    if let Some(mut transfer) = context.workspace().resumable_upload(&request).await? {
        if request.bot_auto {
            request.bot_id = transfer.bot_id;
        }
        if transfer.bot_id != request.bot_id {
            return Err(CoreError::Conflict(
                "the staged upload uses a different publication identity; restart it first"
                    .to_string(),
            ));
        }
        let path = context.transfer_path(transfer.id);
        let actual = match tokio::fs::metadata(&path).await {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        if actual > request.size {
            return Err(CoreError::Conflict(
                "staged content exceeds the declared file size".to_string(),
            ));
        }
        if actual > 0 {
            let expected = request.prefix_sha256.as_deref().ok_or_else(|| {
                CoreError::Conflict(
                    "reselect the source and supply its staged-prefix SHA-256 before resuming"
                        .to_string(),
                )
            })?;
            let actual_hash = sha256_file(&path).await?;
            if !constant_time_eq::constant_time_eq(expected.as_bytes(), actual_hash.as_bytes()) {
                return Err(CoreError::Conflict(
                    "the reselected source does not match staged content; start a new upload"
                        .to_string(),
                ));
            }
        }
        transfer.transferred = actual;
        transfer.status = TransferStatus::Staging;
        transfer.error = None;
        transfer.updated_at = Utc::now();
        context.workspace().put_transfer(&transfer).await?;
        let next_offset = transfer.transferred;
        notify(context, transfer.clone());
        return Ok(UploadResponse {
            transfer,
            next_offset,
        });
    }

    let now = Utc::now();
    let transfer = Transfer {
        id: Uuid::new_v4(),
        direction: TransferDirection::Upload,
        status: TransferStatus::Staging,
        name: request.name.trim().to_string(),
        folder_id: request.folder_id.clone(),
        size: request.size,
        transferred: 0,
        mime_type: request.mime_type.clone(),
        source_modified_ms: request.source_modified_ms,
        source_file_id: None,
        protected: request.protected,
        bot_id: request.bot_id,
        error: None,
        created_at: now,
        updated_at: now,
    };
    let path = context.transfer_path(transfer.id);
    create_private_file(&path).await?;
    context.workspace().put_transfer(&transfer).await?;
    notify(context, transfer.clone());
    Ok(UploadResponse {
        transfer,
        next_offset: 0,
    })
}

pub async fn append_upload<R: AsyncRead + Unpin>(
    guard: &AccountGuard,
    id: Uuid,
    offset: u64,
    reader: &mut R,
) -> Result<UploadResponse> {
    guard.validate()?;
    let context = guard.context();
    let mut transfer = required_transfer(context, id, TransferDirection::Upload).await?;
    if !matches!(
        transfer.status,
        TransferStatus::Staging | TransferStatus::Failed
    ) {
        return Err(CoreError::Conflict(
            "upload is not accepting content".to_string(),
        ));
    }
    if transfer.transferred != offset {
        return Err(CoreError::Conflict(format!(
            "upload offset mismatch; next offset is {}",
            transfer.transferred
        )));
    }
    let remaining = transfer
        .size
        .checked_sub(offset)
        .ok_or_else(|| CoreError::Conflict("upload exceeds its declared size".to_string()))?;
    if remaining == 0 {
        return Err(CoreError::InvalidInput(
            "upload is already complete".to_string(),
        ));
    }
    let path = context.transfer_path(id);
    let actual = tokio::fs::metadata(&path).await?.len();
    if actual < offset {
        return Err(CoreError::Conflict(
            "staged content is missing; restart the upload".to_string(),
        ));
    }
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .await?;
    file.set_len(offset).await?;
    file.seek(std::io::SeekFrom::Start(offset)).await?;

    let mut buffer = vec![0_u8; 64 * 1024];
    let mut received = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        received = received
            .checked_add(read as u64)
            .ok_or_else(|| CoreError::InvalidInput("chunk is too large".to_string()))?;
        if received > MAX_BROWSER_CHUNK_BYTES || received > remaining {
            return Err(CoreError::InvalidInput(
                "chunk exceeds the allowed or remaining size".to_string(),
            ));
        }
        file.write_all(&buffer[..read]).await?;
    }
    if received == 0 {
        return Err(CoreError::InvalidInput("upload chunk is empty".to_string()));
    }
    file.sync_all().await?;
    if context
        .workspace()
        .transfer(id)
        .await?
        .ok_or(CoreError::NotFound)?
        .status
        == TransferStatus::Cancelled
    {
        let _ = tokio::fs::remove_file(&path).await;
        return Err(CoreError::Conflict("transfer was cancelled".to_string()));
    }
    transfer.transferred = offset + received;
    transfer.status = TransferStatus::Staging;
    transfer.error = None;
    transfer.updated_at = Utc::now();
    guard.validate()?;
    context.workspace().put_transfer(&transfer).await?;
    let next_offset = transfer.transferred;
    notify(context, transfer.clone());
    Ok(UploadResponse {
        transfer,
        next_offset,
    })
}

pub async fn complete_upload(guard: &AccountGuard, id: Uuid) -> Result<CompleteUploadResponse> {
    guard.validate()?;
    let context = guard.context();
    let mut transfer = required_transfer(context, id, TransferDirection::Upload).await?;
    if transfer.transferred != transfer.size {
        return Err(CoreError::Conflict(format!(
            "upload is incomplete; next offset is {}",
            transfer.transferred
        )));
    }
    let path = context.transfer_path(id);
    if tokio::fs::metadata(&path).await?.len() != transfer.size {
        return Err(CoreError::Conflict(
            "staged content length does not match the upload".to_string(),
        ));
    }
    transfer.status = TransferStatus::Publishing;
    transfer.updated_at = Utc::now();
    context.workspace().put_transfer(&transfer).await?;
    notify(context, transfer.clone());

    let result = async {
        let transport = context.transport().await?;
        let file = if let Some(bot_id) = transfer.bot_id {
            context
                .bots()
                .publish(
                    bot_id,
                    &path,
                    transfer.folder_id.as_deref(),
                    &transfer.name,
                    &transfer.mime_type,
                )
                .await?
        } else {
            transport
                .publish_file(
                    &path,
                    transfer.folder_id.as_deref(),
                    &transfer.name,
                    &transfer.mime_type,
                )
                .await?
        };
        guard.validate()?;
        if file.size != transfer.size {
            return Err(CoreError::Unavailable(
                "Telegram returned an unexpected file size".to_string(),
            ));
        }
        Ok(file)
    }
    .await;

    match result {
        Ok(file) => {
            let current = context
                .workspace()
                .transfer(id)
                .await?
                .ok_or(CoreError::NotFound)?;
            if current.status == TransferStatus::Cancelled {
                if let Ok(transport) = context.transport().await {
                    let _ = transport.delete_file(&file.id).await;
                }
                let _ = tokio::fs::remove_file(&path).await;
                return Err(CoreError::Conflict("transfer was cancelled".to_string()));
            }
            guard.validate()?;
            context
                .workspace()
                .cache_files(std::slice::from_ref(&file))
                .await?;
            transfer.status = TransferStatus::Completed;
            transfer.error = None;
            transfer.updated_at = Utc::now();
            context.workspace().put_transfer(&transfer).await?;
            let _ = tokio::fs::remove_file(&path).await;
            notify(context, transfer.clone());
            context.notify(ServerEvent::InventoryChanged {
                folder_id: transfer.folder_id.clone(),
                revision: Utc::now().timestamp_millis().max(0) as u64,
            });
            Ok(CompleteUploadResponse { transfer, file })
        }
        Err(error) => {
            transfer.status = TransferStatus::Failed;
            transfer.error = Some(public_error(&error));
            transfer.updated_at = Utc::now();
            context.workspace().put_transfer(&transfer).await?;
            notify(context, transfer);
            Err(error)
        }
    }
}

pub async fn prepare_download(guard: &AccountGuard, file_id: &str) -> Result<DownloadResponse> {
    guard.validate()?;
    let context = guard.context();
    let file = match context.workspace().cached_file(file_id).await? {
        Some(file) => file,
        None => context.transport().await?.file_metadata(file_id).await?,
    };
    let now = Utc::now();
    let mut transfer = Transfer {
        id: Uuid::new_v4(),
        direction: TransferDirection::Download,
        status: TransferStatus::Publishing,
        name: file.name.clone(),
        folder_id: file.folder_id.clone(),
        size: file.size,
        transferred: 0,
        mime_type: file.mime_type.clone(),
        source_modified_ms: None,
        source_file_id: Some(file.id.clone()),
        protected: file.protected,
        bot_id: None,
        error: None,
        created_at: now,
        updated_at: now,
    };
    context.workspace().put_transfer(&transfer).await?;
    notify(context, transfer.clone());
    let path = context.transfer_path(transfer.id);
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let result = async {
        let transport = context.transport().await?;
        let downloaded = transport.download_file(file_id, &path).await?;
        guard.validate()?;
        if downloaded.id != file.id {
            return Err(CoreError::Unauthorized);
        }
        let actual = tokio::fs::metadata(&path).await?.len();
        if actual != file.size {
            return Err(CoreError::Unavailable(
                "download length did not match Telegram metadata".to_string(),
            ));
        }
        Ok(downloaded)
    }
    .await;

    match result {
        Ok(file) => {
            let current = context
                .workspace()
                .transfer(transfer.id)
                .await?
                .ok_or(CoreError::NotFound)?;
            if current.status == TransferStatus::Cancelled {
                let _ = tokio::fs::remove_file(&path).await;
                return Err(CoreError::Conflict("transfer was cancelled".to_string()));
            }
            transfer.status = TransferStatus::Ready;
            transfer.transferred = transfer.size;
            transfer.updated_at = Utc::now();
            context.workspace().put_transfer(&transfer).await?;
            notify(context, transfer.clone());
            let download_url = format!("/api/v1/transfers/{}/content", transfer.id);
            Ok(DownloadResponse {
                transfer,
                file,
                download_url,
            })
        }
        Err(error) => {
            let _ = tokio::fs::remove_file(&path).await;
            transfer.status = TransferStatus::Failed;
            transfer.error = Some(public_error(&error));
            transfer.updated_at = Utc::now();
            context.workspace().put_transfer(&transfer).await?;
            notify(context, transfer);
            Err(error)
        }
    }
}

pub async fn download_path(guard: &AccountGuard, id: Uuid) -> Result<(Transfer, PathBuf)> {
    guard.validate()?;
    let context = guard.context();
    let transfer = required_transfer(context, id, TransferDirection::Download).await?;
    if !matches!(
        transfer.status,
        TransferStatus::Ready | TransferStatus::Completed
    ) {
        return Err(CoreError::Conflict("download is not ready".to_string()));
    }
    let path = context.transfer_path(id);
    if tokio::fs::metadata(&path).await?.len() != transfer.size {
        return Err(CoreError::Conflict(
            "staged download is incomplete".to_string(),
        ));
    }
    Ok((transfer, path))
}

pub async fn list_transfers(guard: &AccountGuard) -> Result<Vec<Transfer>> {
    guard.validate()?;
    guard.context().workspace().transfers().await
}

pub async fn cancel_transfer(guard: &AccountGuard, id: Uuid) -> Result<Transfer> {
    guard.validate()?;
    let context = guard.context();
    let mut transfer = context
        .workspace()
        .transfer(id)
        .await?
        .ok_or(CoreError::NotFound)?;
    if matches!(
        transfer.status,
        TransferStatus::Completed | TransferStatus::Cancelled
    ) {
        return Err(CoreError::Conflict(
            "transfer is already terminal".to_string(),
        ));
    }
    transfer.status = TransferStatus::Cancelled;
    transfer.updated_at = Utc::now();
    transfer.error = None;
    context.workspace().put_transfer(&transfer).await?;
    let _ = tokio::fs::remove_file(context.transfer_path(id)).await;
    notify(context, transfer.clone());
    Ok(transfer)
}

async fn required_transfer(
    context: &std::sync::Arc<crate::accounts::AccountContext>,
    id: Uuid,
    direction: TransferDirection,
) -> Result<Transfer> {
    let transfer = context
        .workspace()
        .transfer(id)
        .await?
        .ok_or(CoreError::NotFound)?;
    if transfer.direction != direction {
        return Err(CoreError::NotFound);
    }
    Ok(transfer)
}

fn validate_upload(request: &CreateUploadRequest) -> Result<()> {
    let name = request.name.trim();
    if name.is_empty()
        || name.chars().count() > 255
        || name.contains(['/', '\\'])
        || name.chars().any(char::is_control)
    {
        return Err(CoreError::InvalidInput(
            "file name must be a valid basename of 1–255 characters".to_string(),
        ));
    }
    if request.size > MAX_TRANSFER_BYTES {
        return Err(CoreError::InvalidInput(
            "file exceeds the 2,000,000,000-byte transfer limit".to_string(),
        ));
    }
    if request.bot_id.is_some() && request.size > 50 * 1024 * 1024 {
        return Err(CoreError::InvalidInput(
            "Bot API uploads are limited to 50 MiB; use your personal account for larger files"
                .to_string(),
        ));
    }
    if request.mime_type.is_empty()
        || request.mime_type.len() > 200
        || request.mime_type.chars().any(char::is_control)
    {
        return Err(CoreError::InvalidInput("invalid media type".to_string()));
    }
    if request.protected
        && (!(name.starts_with("TDENC2") || name.ends_with(".tdenc2") || name.ends_with(".tdenc"))
            || request.mime_type != "application/octet-stream")
    {
        return Err(CoreError::InvalidInput(
            "protected uploads require a generic TDENC2 name and ciphertext media type".to_string(),
        ));
    }
    Ok(())
}

async fn create_private_file(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(path).await?;
    file.sync_all().await?;
    Ok(())
}

async fn sha256_file(path: &Path) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn notify(context: &crate::accounts::AccountContext, transfer: Transfer) {
    context.notify(ServerEvent::TransferUpdated { transfer });
}

fn public_error(error: &CoreError) -> String {
    match error {
        CoreError::InvalidInput(message)
        | CoreError::Conflict(message)
        | CoreError::Unavailable(message) => message.clone(),
        CoreError::Unauthorized => "account session changed".to_string(),
        CoreError::NotFound => "file was not found".to_string(),
        CoreError::RateLimited => "too many attempts; wait before trying again".to_string(),
        CoreError::Storage(_) | CoreError::Internal(_) => {
            "transfer could not be completed".to_string()
        }
    }
}
