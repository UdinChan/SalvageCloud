use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, patch, post, put},
};
use salvage_backend_core::{
    CoreError, Result,
    accounts::{AccountRegistry, SessionCipher},
    auth::AuthService,
    shares::ShareService,
    store::ServiceStore,
    telegram::{
        TelegramFactory,
        bots::{BotFactory, LiveBotFactory},
        live::LiveTelegramFactory,
    },
};
use tower_http::services::ServeDir;

use crate::{
    events,
    middleware::{
        OriginPolicy, SecurityHeaderState, content_security_policy, require_origin,
        security_headers,
    },
    routes,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportChoice {
    Grammers,
    Fixture,
}

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub web_dist: PathBuf,
    pub public_origin: String,
    pub cookie_secure: bool,
    pub session_key: String,
    pub transport: TransportChoice,
    pub channel_part_limit: u64,
    pub telegram_api_id: Option<i32>,
    pub telegram_api_hash: Option<String>,
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let bind = std::env::var("SALVAGE_BIND")
            .unwrap_or_else(|_| "127.0.0.1:3000".to_string())
            .parse()
            .map_err(|_| {
                CoreError::InvalidInput("SALVAGE_BIND is not a valid socket address".to_string())
            })?;
        let public_origin =
            std::env::var("SALVAGE_PUBLIC_ORIGIN").unwrap_or_else(|_| format!("http://{bind}"));
        let transport = match std::env::var("SALVAGE_TELEGRAM_TRANSPORT")
            .unwrap_or_else(|_| "grammers".to_string())
            .as_str()
        {
            "grammers" => TransportChoice::Grammers,
            "fixture" => TransportChoice::Fixture,
            _ => {
                return Err(CoreError::InvalidInput(
                    "SALVAGE_TELEGRAM_TRANSPORT must be grammers or fixture".to_string(),
                ));
            }
        };
        let telegram_api_id = std::env::var("TELEGRAM_API_ID")
            .ok()
            .map(|value| {
                value.parse().map_err(|_| {
                    CoreError::InvalidInput("TELEGRAM_API_ID must be an integer".to_string())
                })
            })
            .transpose()?;
        let telegram_api_hash = std::env::var("TELEGRAM_API_HASH")
            .ok()
            .filter(|value| !value.is_empty());
        if transport == TransportChoice::Grammers
            && (telegram_api_id.is_none() || telegram_api_hash.is_none())
        {
            return Err(CoreError::InvalidInput(
                "live transport requires TELEGRAM_API_ID and TELEGRAM_API_HASH".to_string(),
            ));
        }
        Ok(Self {
            bind,
            data_dir: std::env::var("SALVAGE_DATA_DIR")
                .unwrap_or_else(|_| "./data".to_string())
                .into(),
            web_dist: std::env::var("SALVAGE_WEB_DIST")
                .unwrap_or_else(|_| "./dist".to_string())
                .into(),
            public_origin,
            cookie_secure: std::env::var("SALVAGE_COOKIE_SECURE")
                .map(|value| value == "true")
                .unwrap_or(true),
            session_key: std::env::var("SALVAGE_SESSION_KEY").map_err(|_| {
                CoreError::InvalidInput("SALVAGE_SESSION_KEY is required".to_string())
            })?,
            transport,
            channel_part_limit: std::env::var("SALVAGE_CHANNEL_PART_LIMIT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(500_000),
            telegram_api_id,
            telegram_api_hash,
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    pub auth: Arc<AuthService>,
    pub shares: Arc<ShareService>,
    pub public_origin: Arc<str>,
    pub cookie_secure: bool,
}

pub async fn build_app(config: Config) -> Result<Router> {
    tokio::fs::create_dir_all(&config.data_dir).await?;
    let service_store = ServiceStore::open(&config.data_dir.join("salvage.db")).await?;
    let sessions = SessionCipher::from_hex(&config.session_key)?;
    let origin_policy = OriginPolicy::new(
        config.public_origin.clone(),
        matches!(config.transport, TransportChoice::Fixture),
    );
    let (factory, bot_factory): (Arc<dyn TelegramFactory>, Arc<dyn BotFactory>) = match config
        .transport
    {
        TransportChoice::Grammers => (
            Arc::new(LiveTelegramFactory::new(
                config.telegram_api_id.unwrap_or_default(),
                config.telegram_api_hash.clone().unwrap_or_default(),
                sessions.clone(),
            )),
            Arc::new(LiveBotFactory::new(
                config.telegram_api_id.unwrap_or_default(),
                config.telegram_api_hash.clone().unwrap_or_default(),
                sessions.clone(),
            )),
        ),
        TransportChoice::Fixture => {
            #[cfg(feature = "e2e-fixture")]
            {
                let fixture =
                    Arc::new(salvage_backend_core::telegram::fixture::FixtureFactory::new());
                let bots = Arc::new(
                    salvage_backend_core::telegram::bot_fixture::FixtureBotFactory::new(&fixture),
                );
                (fixture, bots)
            }
            #[cfg(not(feature = "e2e-fixture"))]
            {
                return Err(CoreError::InvalidInput(
                    "fixture transport requires the e2e-fixture feature".to_string(),
                ));
            }
        }
    };
    let registry = Arc::new(AccountRegistry::new(
        &config.data_dir,
        factory.clone(),
        bot_factory,
        sessions.clone(),
        config.channel_part_limit,
    ));
    let auth = Arc::new(AuthService::new(
        service_store.clone(),
        registry.clone(),
        factory,
        sessions,
    ));
    let shares = Arc::new(ShareService::new(service_store, registry));
    let state = AppState {
        auth: auth.clone(),
        shares: shares.clone(),
        public_origin: Arc::from(config.public_origin.clone()),
        cookie_secure: config.cookie_secure,
    };

    let cleanup_auth = auth.clone();
    let cleanup_shares = shares.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let _ = cleanup_auth.cleanup().await;
            let _ = cleanup_shares.cleanup_expired().await;
        }
    });

    let api = Router::new()
        .route("/auth/session", get(routes::session))
        .route("/auth/phone", post(routes::phone_login))
        .route("/auth/qr", post(routes::begin_qr_login))
        .route("/auth/qr/{id}", post(routes::poll_qr_login))
        .route("/auth/code", post(routes::verify_code))
        .route("/auth/password", post(routes::verify_password))
        .route("/auth/logout", post(routes::logout))
        .route("/bots", get(routes::list_bots).post(routes::add_bot))
        .route("/bots/{id}", delete(routes::delete_bot))
        .route("/bots/{id}/provision", post(routes::provision_bot))
        .route(
            "/folders",
            get(routes::list_folders).post(routes::create_folder),
        )
        .route(
            "/folders/{id}",
            patch(routes::rename_folder).delete(routes::delete_folder),
        )
        .route("/channels/{id}/activate", post(routes::activate_folder))
        .route("/files", get(routes::list_files))
        .route("/files/{id}", delete(routes::delete_file))
        .route(
            "/files/{id}/shares",
            get(routes::list_shares).post(routes::create_share),
        )
        .route("/shares/{id}", delete(routes::revoke_share))
        .route("/transfers", get(routes::list_transfers))
        .route("/transfers/uploads", post(routes::create_upload))
        .route(
            "/transfers/uploads/{id}/content",
            put(routes::append_upload).layer(DefaultBodyLimit::max(
                salvage_backend_core::transfers::MAX_BROWSER_CHUNK_BYTES as usize,
            )),
        )
        .route(
            "/transfers/uploads/{id}/complete",
            post(routes::complete_upload),
        )
        .route(
            "/transfers/downloads/{file_id}",
            post(routes::prepare_download),
        )
        .route("/transfers/{id}/content", get(routes::download_content))
        .route("/transfers/{id}", delete(routes::cancel_transfer))
        .route("/events", get(events::events))
        .fallback(routes::api_not_found)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(middleware::from_fn_with_state(
            origin_policy,
            require_origin,
        ))
        .with_state(state.clone());

    let index = config.web_dist.join("index.html");
    let index_html = tokio::fs::read_to_string(&index).await?;
    let security = SecurityHeaderState::new(index.clone(), content_security_policy(&index_html)?);
    let static_files = ServeDir::new(&config.web_dist).fallback(get(routes::spa).with_state(index));
    Ok(Router::new()
        .route("/api/health", get(routes::health))
        .route("/s/{token}", get(routes::public_share))
        .nest("/api/v1", api)
        .fallback_service(static_files)
        .layer(middleware::from_fn_with_state(security, security_headers))
        .with_state(state))
}
