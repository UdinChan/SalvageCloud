use std::{path::PathBuf, sync::Arc};

use salvage_backend_core::{
    accounts::SessionCipher,
    bot_service::BotService,
    store::WorkspaceStore,
    telegram::{
        TelegramFactory,
        bots::{BotFactory, LiveBotFactory},
        live::LiveTelegramFactory,
    },
};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("Live Telegram download E2E failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let account_dir = PathBuf::from(
        std::env::var("SALVAGE_LIVE_ACCOUNT_DIR")
            .map_err(|_| "SALVAGE_LIVE_ACCOUNT_DIR is required".to_string())?,
    );
    let file_id = std::env::var("SALVAGE_LIVE_FILE_ID")
        .map_err(|_| "SALVAGE_LIVE_FILE_ID is required".to_string())?;
    let api_id = std::env::var("TELEGRAM_API_ID")
        .map_err(|_| "TELEGRAM_API_ID is required".to_string())?
        .parse::<i32>()
        .map_err(|_| "TELEGRAM_API_ID is invalid".to_string())?;
    let api_hash = std::env::var("TELEGRAM_API_HASH")
        .map_err(|_| "TELEGRAM_API_HASH is required".to_string())?;
    let session_key = std::env::var("SALVAGE_SESSION_KEY")
        .map_err(|_| "SALVAGE_SESSION_KEY is required".to_string())?;
    let cipher = SessionCipher::from_hex(&session_key).map_err(|error| error.to_string())?;
    let encrypted = cipher
        .load(&account_dir)
        .await
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "encrypted Telegram session was not found".to_string())?;
    let factory = LiveTelegramFactory::new(api_id, api_hash.clone(), cipher.clone());
    let transport = factory
        .restore(&encrypted)
        .await
        .map_err(|error| error.to_string())?;
    let expected_user_id = std::env::var("SALVAGE_LIVE_TELEGRAM_USER_ID")
        .map_err(|_| "SALVAGE_LIVE_TELEGRAM_USER_ID is required".to_string())?
        .parse::<i64>()
        .map_err(|_| "SALVAGE_LIVE_TELEGRAM_USER_ID is invalid".to_string())?;
    let actual_user = transport
        .self_user()
        .ok_or_else(|| "restored Telegram self user is unavailable".to_string())?;
    if actual_user.id != expected_user_id {
        return Err("encrypted session belongs to a different Telegram account".to_string());
    }
    if let (Ok(bot_id), Ok(channel_id)) = (
        std::env::var("SALVAGE_LIVE_BOT_ID"),
        std::env::var("SALVAGE_LIVE_CHANNEL_ID"),
    ) {
        let bot_id = uuid::Uuid::parse_str(&bot_id).map_err(|_| "bot ID is invalid".to_string())?;
        let workspace = WorkspaceStore::open(&account_dir.join("workspace.db"))
            .await
            .map_err(|error| error.to_string())?;
        let bots = BotService::new(
            Arc::new(LiveBotFactory::new(
                api_id,
                api_hash.clone(),
                cipher.clone(),
            )),
            workspace,
            cipher.clone(),
        );
        if std::env::var("SALVAGE_LIVE_PROVISION").as_deref() == Ok("1") {
            bots.provision(bot_id, transport.clone())
                .await
                .map_err(|error| format!("stored bot provisioning: {error}"))?;
            println!("{{\"status\":\"ok\",\"stored_bot_provisioned\":true}}");
            return Ok(());
        }
        bots.validate_upload(bot_id, Some(&channel_id))
            .await
            .map_err(|error| format!("stored bot authorization: {error}"))?;
        let source = std::env::temp_dir().join(format!(
            "salvage-live-stored-bot-upload-{}",
            uuid::Uuid::new_v4()
        ));
        let expected = b"Salvage Cloud stored bot acceptance\n";
        let test_name = std::env::var("SALVAGE_LIVE_TEST_FILE_NAME")
            .unwrap_or_else(|_| "salvage-live-stored-bot.txt".to_string());
        let test_mime =
            std::env::var("SALVAGE_LIVE_TEST_MIME").unwrap_or_else(|_| "text/plain".to_string());
        tokio::fs::write(&source, expected)
            .await
            .map_err(|error| error.to_string())?;
        let uploaded = bots
            .publish(bot_id, &source, Some(&channel_id), &test_name, &test_mime)
            .await
            .map_err(|error| format!("stored bot publication: {error}"))?;
        if uploaded.name != test_name || uploaded.mime_type != test_mime {
            return Err(format!(
                "uploaded metadata differs: name={}, mime={}",
                uploaded.name, uploaded.mime_type
            ));
        }
        let destination = std::env::temp_dir().join(format!(
            "salvage-live-stored-bot-download-{}",
            uuid::Uuid::new_v4()
        ));
        let result = async {
            transport
                .file_metadata(&uploaded.id)
                .await
                .map_err(|error| format!("stored bot metadata lookup: {error}"))?;
            transport
                .download_file(&uploaded.id, &destination)
                .await
                .map_err(|error| format!("stored bot content download: {error}"))?;
            let actual = tokio::fs::read(&destination)
                .await
                .map_err(|error| error.to_string())?;
            if actual != expected {
                return Err("stored bot upload bytes differ".to_string());
            }
            Ok(())
        }
        .await;
        let cleanup = transport.delete_file(&uploaded.id).await;
        let _ = tokio::fs::remove_file(&source).await;
        let _ = tokio::fs::remove_file(&destination).await;
        result?;
        cleanup.map_err(|error| format!("stored bot-message cleanup: {error}"))?;
        println!("{{\"status\":\"ok\",\"stored_bot_upload_download_delete\":true}}");
        return Ok(());
    }
    if let (Ok(token), Ok(channel_id)) = (
        std::env::var("SALVAGE_LIVE_BOT_TOKEN"),
        std::env::var("SALVAGE_LIVE_CHANNEL_ID"),
    ) {
        let bot_factory = LiveBotFactory::new(api_id, api_hash, cipher);
        let bot = bot_factory
            .sign_in(&token)
            .await
            .map_err(|error| format!("bot sign-in: {error}"))?;
        if !bot
            .can_upload(&channel_id)
            .await
            .map_err(|error| format!("bot administrator check: {error}"))?
        {
            return Err("bot lacks administrator access in the selected channel".to_string());
        }
        let source =
            std::env::temp_dir().join(format!("salvage-live-bot-upload-{}", uuid::Uuid::new_v4()));
        let expected = b"Salvage Cloud live bot acceptance\n";
        tokio::fs::write(&source, expected)
            .await
            .map_err(|error| error.to_string())?;
        let uploaded = bot
            .publish_file(&source, &channel_id, "salvage-live-bot.txt", "text/plain")
            .await
            .map_err(|error| format!("controlled bot upload: {error}"))?;
        let destination = std::env::temp_dir().join(format!(
            "salvage-live-bot-download-{}",
            uuid::Uuid::new_v4()
        ));
        let result = async {
            transport
                .file_metadata(&uploaded.id)
                .await
                .map_err(|error| format!("bot-upload metadata lookup: {error}"))?;
            transport
                .download_file(&uploaded.id, &destination)
                .await
                .map_err(|error| format!("bot-upload content download: {error}"))?;
            let actual = tokio::fs::read(&destination)
                .await
                .map_err(|error| error.to_string())?;
            if actual != expected {
                return Err("controlled bot upload bytes differ".to_string());
            }
            Ok(())
        }
        .await;
        let cleanup = transport.delete_file(&uploaded.id).await;
        let _ = tokio::fs::remove_file(&source).await;
        let _ = tokio::fs::remove_file(&destination).await;
        result?;
        cleanup.map_err(|error| format!("controlled bot-message cleanup: {error}"))?;
        println!("{{\"status\":\"ok\",\"live_bot_upload_download_delete\":true}}");
        return Ok(());
    }
    if std::env::var("SALVAGE_LIVE_WRITE_TEST").as_deref() == Ok("1") {
        let source =
            std::env::temp_dir().join(format!("salvage-live-upload-{}", uuid::Uuid::new_v4()));
        let expected = b"Salvage Cloud live Telegram acceptance\n";
        tokio::fs::write(&source, expected)
            .await
            .map_err(|error| error.to_string())?;
        let uploaded = transport
            .publish_file(&source, None, "salvage-live-acceptance.txt", "text/plain")
            .await
            .map_err(|error| format!("controlled upload: {error}"))?;
        let destination = std::env::temp_dir().join(format!(
            "salvage-live-write-download-{}",
            uuid::Uuid::new_v4()
        ));
        let result = async {
            transport
                .file_metadata(&uploaded.id)
                .await
                .map_err(|error| format!("uploaded metadata lookup: {error}"))?;
            transport
                .download_file(&uploaded.id, &destination)
                .await
                .map_err(|error| format!("uploaded content download: {error}"))?;
            let actual = tokio::fs::read(&destination)
                .await
                .map_err(|error| error.to_string())?;
            if actual != expected {
                return Err("controlled upload bytes differ after download".to_string());
            }
            Ok(())
        }
        .await;
        let cleanup = transport.delete_file(&uploaded.id).await;
        let _ = tokio::fs::remove_file(&source).await;
        let _ = tokio::fs::remove_file(&destination).await;
        result?;
        cleanup.map_err(|error| format!("controlled test-message cleanup: {error}"))?;
        println!("{{\"status\":\"ok\",\"live_upload_download_delete\":true}}");
        return Ok(());
    }
    let listed = transport
        .list_files(None, None)
        .await
        .map_err(|error| format!("root listing: {error}"))?;
    let selected_is_listed = listed.iter().any(|file| file.id == file_id);
    eprintln!(
        "Live driver listed {} root files; selected file listed: {selected_is_listed}",
        listed.len()
    );
    let file_id = if file_id == "latest" {
        listed
            .first()
            .map(|file| file.id.clone())
            .ok_or_else(|| "no current root file is available for download".to_string())?
    } else {
        file_id
    };
    let metadata = transport
        .file_metadata(&file_id)
        .await
        .map_err(|error| format!("metadata lookup: {error}"))?;

    let destination =
        std::env::temp_dir().join(format!("salvage-live-download-{}", uuid::Uuid::new_v4()));
    let result = async {
        let downloaded = transport
            .download_file(&file_id, &destination)
            .await
            .map_err(|error| format!("content download: {error}"))?;
        let actual = tokio::fs::metadata(&destination)
            .await
            .map_err(|error| error.to_string())?
            .len();
        if actual != metadata.size {
            return Err(format!(
                "downloaded length {actual} differs from Telegram metadata {}",
                metadata.size
            ));
        }
        if downloaded.id != metadata.id {
            return Err("downloaded file identity differs".to_string());
        }
        Ok(actual)
    }
    .await;
    let _ = tokio::fs::remove_file(&destination).await;
    drop(transport);
    let bytes = result?;
    println!("{{\"status\":\"ok\",\"live_download\":true,\"bytes\":{bytes}}}");
    Ok(())
}
