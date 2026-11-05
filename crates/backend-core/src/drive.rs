use salvage_protocol::{CreateFolderRequest, FilePage, Folder, RenameFolderRequest, ServerEvent};

use crate::{CoreError, Result, accounts::AccountGuard};

pub async fn list_folders(guard: &AccountGuard, parent_id: Option<&str>) -> Result<Vec<Folder>> {
    guard.validate()?;
    let context = guard.context();
    let transport = context.transport().await?;
    let active_id = context.workspace().active_channel().await?;
    let mut folders = transport.list_folders(parent_id).await?;
    for folder in &mut folders {
        folder.active = active_id.as_deref() == Some(folder.id.as_str());
        context.workspace().cache_folder(folder).await?;
    }
    Ok(folders)
}

pub async fn activate_folder(guard: &AccountGuard, id: &str) -> Result<Folder> {
    guard.validate()?;
    let context = guard.context();
    let transport = context.transport().await?;
    let mut folder = transport
        .list_folders(None)
        .await?
        .into_iter()
        .find(|folder| folder.id == id)
        .ok_or(CoreError::NotFound)?;
    folder.active = true;
    context.workspace().set_active_channel(id).await?;
    context.workspace().cache_folder(&folder).await?;
    context.notify(ServerEvent::InventoryChanged {
        folder_id: None,
        revision: revision(),
    });
    Ok(folder)
}

pub async fn create_folder(guard: &AccountGuard, request: CreateFolderRequest) -> Result<Folder> {
    guard.validate()?;
    let name = validated_name(&request.name)?;
    let context = guard.context();
    let transport = context.transport().await?;
    let folder = transport
        .create_folder(request.parent_id.as_deref(), name)
        .await?;
    guard.validate()?;
    for bot in context.bots().list().await? {
        if let Some(username) = bot.bot_username {
            transport.provision_bot(&folder.id, &username).await?;
        }
    }
    context.workspace().cache_folder(&folder).await?;
    context.notify(ServerEvent::InventoryChanged {
        folder_id: folder.parent_id.clone(),
        revision: revision(),
    });
    Ok(folder)
}

pub async fn rename_folder(
    guard: &AccountGuard,
    id: &str,
    request: RenameFolderRequest,
) -> Result<Folder> {
    guard.validate()?;
    let name = validated_name(&request.name)?;
    let context = guard.context();
    let transport = context.transport().await?;
    let folder = transport.rename_folder(id, name).await?;
    guard.validate()?;
    context.workspace().cache_folder(&folder).await?;
    context.notify(ServerEvent::InventoryChanged {
        folder_id: folder.parent_id.clone(),
        revision: revision(),
    });
    Ok(folder)
}

pub async fn delete_folder(guard: &AccountGuard, id: &str) -> Result<()> {
    guard.validate()?;
    let context = guard.context();
    let transport = context.transport().await?;
    transport.delete_folder(id).await?;
    guard.validate()?;
    context.workspace().remove_folder(id).await?;
    context.notify(ServerEvent::InventoryChanged {
        folder_id: None,
        revision: revision(),
    });
    Ok(())
}

pub async fn list_files(
    guard: &AccountGuard,
    folder_id: Option<&str>,
    query: Option<&str>,
) -> Result<FilePage> {
    guard.validate()?;
    let query = query.map(str::trim).filter(|value| !value.is_empty());
    if query.is_some_and(|value| value.len() > 200) {
        return Err(CoreError::InvalidInput(
            "search query is too long".to_string(),
        ));
    }
    let context = guard.context();
    let transport = context.transport().await?;
    let files = transport.list_files(folder_id, query).await?;
    guard.validate()?;
    context.workspace().cache_files(&files).await?;
    Ok(FilePage {
        files,
        next_cursor: None,
        complete: true,
    })
}

pub async fn delete_file(guard: &AccountGuard, id: &str) -> Result<()> {
    guard.validate()?;
    let context = guard.context();
    let transport = context.transport().await?;
    transport.delete_file(id).await?;
    guard.validate()?;
    context.workspace().remove_file(id).await?;
    context.notify(ServerEvent::InventoryChanged {
        folder_id: None,
        revision: revision(),
    });
    Ok(())
}

fn validated_name(value: &str) -> Result<&str> {
    let name = value.trim();
    if name.is_empty() || name.chars().count() > 100 || name.chars().any(char::is_control) {
        return Err(CoreError::InvalidInput(
            "folder names must contain 1–100 visible characters".to_string(),
        ));
    }
    Ok(name)
}

fn revision() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}
