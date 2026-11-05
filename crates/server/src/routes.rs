use std::path::PathBuf;

use axum::{
    Json,
    body::Body,
    extract::{FromRequestParts, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, request::Parts},
    response::{Html, IntoResponse, Response},
};
use futures_util::StreamExt as _;
use salvage_backend_core::{
    CoreError,
    accounts::AccountGuard,
    auth::{AuthService, AuthenticatedAccount, IssuedSession},
    drive, transfers,
};
use salvage_protocol::{
    AddBotTokenRequest, BotTokenInfo, CloudPasswordRequest, CompleteUploadResponse,
    CreateFolderRequest, CreateShareRequest, CreateUploadRequest, CreatedShare, DownloadResponse,
    ErrorResponse, HealthResponse, LoginAttemptResponse, LoginOutcome, PhoneLoginRequest,
    QrLoginAttemptResponse, RenameFolderRequest, SessionResponse, Share, Transfer, UploadResponse,
    VerifyCodeRequest,
};
use serde::Deserialize;
use tower::ServiceExt as _;
use tower_http::services::ServeFile;
use uuid::Uuid;

use crate::app::AppState;

const SESSION_COOKIE: &str = "salvage_session";
const SESSION_MAX_AGE: u64 = 30 * 24 * 60 * 60;

pub type ApiResult<T> = std::result::Result<T, ApiError>;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

impl From<CoreError> for ApiError {
    fn from(error: CoreError) -> Self {
        match error {
            CoreError::InvalidInput(message) => {
                Self::new(StatusCode::BAD_REQUEST, "invalid_request", &message)
            }
            CoreError::Unauthorized => Self::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication is required or the supplied credentials are invalid",
            ),
            CoreError::NotFound => Self::new(
                StatusCode::NOT_FOUND,
                "not_found",
                "the requested object was not found",
            ),
            CoreError::Conflict(message) => Self::new(StatusCode::CONFLICT, "conflict", &message),
            CoreError::Unavailable(message) => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "telegram_unavailable",
                &message,
            ),
            CoreError::RateLimited => Self::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many authentication attempts; wait before trying again",
            ),
            CoreError::Storage(_) | CoreError::Internal(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "the operation could not be completed",
            ),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                code: self.code,
                message: self.message,
            }),
        )
            .into_response()
    }
}

pub struct RequestAuth {
    pub authenticated: AuthenticatedAccount,
    pub guard: AccountGuard,
}

impl RequestAuth {
    fn csrf(&self, headers: &HeaderMap) -> ApiResult<()> {
        let supplied = headers
            .get("x-csrf-token")
            .and_then(|value| value.to_str().ok());
        AuthService::validate_csrf(&self.authenticated, supplied).map_err(Into::into)
    }
}

impl FromRequestParts<AppState> for RequestAuth {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let token = session_token(&parts.headers).ok_or_else(|| {
            ApiError::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication is required",
            )
        })?;
        let authenticated = state.auth.authenticate(token).await?;
        let guard = AccountGuard::capture(authenticated.context.clone());
        Ok(Self {
            authenticated,
            guard,
        })
    }
}

pub async fn spa(State(index): State<PathBuf>) -> Response {
    match tokio::fs::read_to_string(index).await {
        Ok(html) => Html(html).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

pub async fn api_not_found() -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "the requested API route was not found",
    )
}

pub async fn session(auth: RequestAuth) -> Json<SessionResponse> {
    Json(AuthService::session_response(&auth.authenticated))
}

pub async fn phone_login(
    State(state): State<AppState>,
    Json(request): Json<PhoneLoginRequest>,
) -> ApiResult<Json<LoginAttemptResponse>> {
    Ok(Json(state.auth.begin_phone_login(&request.phone).await?))
}

pub async fn begin_qr_login(
    State(state): State<AppState>,
) -> ApiResult<Json<QrLoginAttemptResponse>> {
    Ok(Json(state.auth.begin_qr_login().await?))
}

pub async fn poll_qr_login(
    State(state): State<AppState>,
    Path(attempt_id): Path<Uuid>,
) -> ApiResult<Response> {
    let (poll, issued) = state.auth.poll_qr_login(attempt_id).await?;
    let mut response = Json(poll).into_response();
    if let Some(issued) = issued {
        let secure = if state.cookie_secure { "; Secure" } else { "" };
        let cookie = format!(
            "{SESSION_COOKIE}={}; Max-Age={SESSION_MAX_AGE}; Path=/; HttpOnly; SameSite=Strict{secure}",
            issued.token.as_str()
        );
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie)
                .map_err(|_| CoreError::Internal("cookie encoding failed".to_string()))?,
        );
    }
    Ok(response)
}

pub async fn verify_code(
    State(state): State<AppState>,
    Json(request): Json<VerifyCodeRequest>,
) -> ApiResult<Response> {
    let (outcome, issued) = state
        .auth
        .verify_code(request.attempt_id, &request.code)
        .await?;
    login_response(outcome, issued, state.cookie_secure)
}

pub async fn verify_password(
    State(state): State<AppState>,
    Json(request): Json<CloudPasswordRequest>,
) -> ApiResult<Response> {
    let (outcome, issued) = state
        .auth
        .verify_password(request.attempt_id, &request.password)
        .await?;
    login_response(outcome, issued, state.cookie_secure)
}

pub async fn list_bots(auth: RequestAuth) -> ApiResult<Json<Vec<BotTokenInfo>>> {
    Ok(Json(auth.guard.context().bots().list().await?))
}

pub async fn add_bot(
    headers: HeaderMap,
    auth: RequestAuth,
    Json(request): Json<AddBotTokenRequest>,
) -> ApiResult<Json<BotTokenInfo>> {
    auth.csrf(&headers)?;
    let transport = auth.guard.context().transport().await?;
    Ok(Json(
        auth.guard.context().bots().add(request, transport).await?,
    ))
}

pub async fn provision_bot(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<()> {
    auth.csrf(&headers)?;
    let transport = auth.guard.context().transport().await?;
    auth.guard.context().bots().provision(id, transport).await?;
    Ok(())
}

pub async fn delete_bot(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<()> {
    auth.csrf(&headers)?;
    auth.guard.context().bots().remove(id).await?;
    Ok(())
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<Response> {
    auth.csrf(&headers)?;
    let token = session_token(&headers).ok_or(CoreError::Unauthorized)?;
    state.auth.logout(token).await?;
    let mut response = StatusCode::NO_CONTENT.into_response();
    let secure = if state.cookie_secure { "; Secure" } else { "" };
    let cookie = format!("{SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict{secure}");
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&cookie)
            .map_err(|_| CoreError::Internal("cookie encoding failed".to_string()))?,
    );
    Ok(response)
}

fn login_response(
    outcome: LoginOutcome,
    issued: Option<IssuedSession>,
    secure_cookie: bool,
) -> ApiResult<Response> {
    let mut response = Json(outcome).into_response();
    if let Some(issued) = issued {
        let secure = if secure_cookie { "; Secure" } else { "" };
        let cookie = format!(
            "{SESSION_COOKIE}={}; Max-Age={SESSION_MAX_AGE}; Path=/; HttpOnly; SameSite=Strict{secure}",
            issued.token.as_str()
        );
        response.headers_mut().insert(
            header::SET_COOKIE,
            HeaderValue::from_str(&cookie)
                .map_err(|_| CoreError::Internal("cookie encoding failed".to_string()))?,
        );
    }
    Ok(response)
}

#[derive(Deserialize)]
pub struct FolderQuery {
    parent_id: Option<String>,
}

pub async fn list_folders(
    auth: RequestAuth,
    Query(query): Query<FolderQuery>,
) -> ApiResult<Json<Vec<salvage_protocol::Folder>>> {
    Ok(Json(
        drive::list_folders(&auth.guard, query.parent_id.as_deref()).await?,
    ))
}

pub async fn create_folder(
    headers: HeaderMap,
    auth: RequestAuth,
    Json(request): Json<CreateFolderRequest>,
) -> ApiResult<Json<salvage_protocol::Folder>> {
    auth.csrf(&headers)?;
    Ok(Json(drive::create_folder(&auth.guard, request).await?))
}

pub async fn rename_folder(
    Path(id): Path<String>,
    headers: HeaderMap,
    auth: RequestAuth,
    Json(request): Json<RenameFolderRequest>,
) -> ApiResult<Json<salvage_protocol::Folder>> {
    auth.csrf(&headers)?;
    Ok(Json(drive::rename_folder(&auth.guard, &id, request).await?))
}

pub async fn activate_folder(
    Path(id): Path<String>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<Json<salvage_protocol::Folder>> {
    auth.csrf(&headers)?;
    Ok(Json(drive::activate_folder(&auth.guard, &id).await?))
}

pub async fn delete_folder(
    Path(id): Path<String>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<StatusCode> {
    auth.csrf(&headers)?;
    drive::delete_folder(&auth.guard, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct FilesQuery {
    folder_id: Option<String>,
    q: Option<String>,
}

pub async fn list_files(
    auth: RequestAuth,
    Query(query): Query<FilesQuery>,
) -> ApiResult<Json<salvage_protocol::FilePage>> {
    Ok(Json(
        drive::list_files(&auth.guard, query.folder_id.as_deref(), query.q.as_deref()).await?,
    ))
}

pub async fn delete_file(
    Path(id): Path<String>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<StatusCode> {
    auth.csrf(&headers)?;
    drive::delete_file(&auth.guard, &id).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_transfers(auth: RequestAuth) -> ApiResult<Json<Vec<Transfer>>> {
    Ok(Json(transfers::list_transfers(&auth.guard).await?))
}

pub async fn create_upload(
    headers: HeaderMap,
    auth: RequestAuth,
    Json(request): Json<CreateUploadRequest>,
) -> ApiResult<Json<UploadResponse>> {
    auth.csrf(&headers)?;
    Ok(Json(transfers::create_upload(&auth.guard, request).await?))
}

pub async fn append_upload(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    auth: RequestAuth,
    body: Body,
) -> ApiResult<Json<UploadResponse>> {
    auth.csrf(&headers)?;
    let offset = headers
        .get("x-upload-offset")
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| CoreError::InvalidInput("X-Upload-Offset is required".to_string()))?
        .parse::<u64>()
        .map_err(|_| CoreError::InvalidInput("X-Upload-Offset must be an integer".to_string()))?;
    let stream = body
        .into_data_stream()
        .map(|chunk| chunk.map_err(std::io::Error::other));
    let mut reader = tokio_util::io::StreamReader::new(stream);
    Ok(Json(
        transfers::append_upload(&auth.guard, id, offset, &mut reader).await?,
    ))
}

pub async fn complete_upload(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<Json<CompleteUploadResponse>> {
    auth.csrf(&headers)?;
    Ok(Json(transfers::complete_upload(&auth.guard, id).await?))
}

pub async fn prepare_download(
    Path(file_id): Path<String>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<Json<DownloadResponse>> {
    auth.csrf(&headers)?;
    Ok(Json(
        transfers::prepare_download(&auth.guard, &file_id).await?,
    ))
}

pub async fn cancel_transfer(
    Path(id): Path<Uuid>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<Json<Transfer>> {
    auth.csrf(&headers)?;
    Ok(Json(transfers::cancel_transfer(&auth.guard, id).await?))
}

pub async fn download_content(
    Path(id): Path<Uuid>,
    auth: RequestAuth,
    request: Request,
) -> ApiResult<Response> {
    let (transfer, path) = transfers::download_path(&auth.guard, id).await?;
    if request.uri().query() == Some("inline=1") && transfer.protected {
        return Err(
            CoreError::InvalidInput("encrypted files cannot be previewed".to_string()).into(),
        );
    }
    let mode = if request.uri().query() == Some("inline=1") {
        ContentMode::Inline
    } else {
        ContentMode::Attachment
    };
    serve_transfer(request, transfer, path, mode).await
}

pub async fn create_share(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: RequestAuth,
    Json(request): Json<CreateShareRequest>,
) -> ApiResult<Json<CreatedShare>> {
    auth.csrf(&headers)?;
    Ok(Json(
        state
            .shares
            .create(
                &auth.guard,
                &file_id,
                request.expires_in_hours,
                request.expires_in_seconds,
            )
            .await?,
    ))
}

pub async fn list_shares(
    Path(file_id): Path<String>,
    State(state): State<AppState>,
    auth: RequestAuth,
) -> ApiResult<Json<Vec<Share>>> {
    Ok(Json(state.shares.list(&auth.guard, &file_id).await?))
}

pub async fn revoke_share(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    auth: RequestAuth,
) -> ApiResult<Json<Share>> {
    auth.csrf(&headers)?;
    Ok(Json(state.shares.revoke(&auth.guard, id).await?))
}

pub async fn public_share(
    Path(token): Path<String>,
    State(state): State<AppState>,
    request: Request,
) -> ApiResult<Response> {
    let content = state.shares.public_content(&token).await?;
    let mode = if request.uri().query() == Some("download=1") {
        ContentMode::Attachment
    } else {
        ContentMode::Inline
    };
    serve_transfer(request, content.transfer, content.path, mode).await
}

#[derive(Clone, Copy)]
enum ContentMode {
    Inline,
    Attachment,
}

async fn serve_transfer(
    request: Request,
    transfer: Transfer,
    path: std::path::PathBuf,
    mode: ContentMode,
) -> ApiResult<Response> {
    let mode = match mode {
        ContentMode::Inline if inline_media_type(&transfer.mime_type).is_some() => {
            ContentMode::Inline
        }
        _ => ContentMode::Attachment,
    };
    let mut response = ServeFile::new(path)
        .oneshot(request)
        .await
        .expect("ServeFile is infallible")
        .map(Body::new);
    let content_type = HeaderValue::from_str(&transfer.mime_type)
        .unwrap_or_else(|_| HeaderValue::from_static("application/octet-stream"));
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, content_type);
    let safe_name: String = transfer
        .name
        .chars()
        .map(|character| {
            if character.is_control() {
                '_'
            } else {
                character
            }
        })
        .collect();
    let disposition = format!(
        "{}; filename=\"download\"; filename*=UTF-8''{}",
        match mode {
            ContentMode::Inline => "inline",
            ContentMode::Attachment => "attachment",
        },
        urlencoding::encode(&safe_name)
    );
    response.headers_mut().insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&disposition)
            .map_err(|_| CoreError::Internal("download name encoding failed".to_string()))?,
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    Ok(response)
}

fn inline_media_type(mime_type: &str) -> Option<&str> {
    match mime_type {
        "text/plain" | "image/png" | "image/jpeg" | "image/gif" | "image/webp"
        | "application/pdf" => Some(mime_type),
        value if value.starts_with("audio/") || value.starts_with("video/") => Some(value),
        _ => None,
    }
}

fn session_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let (name, value) = cookie.trim().split_once('=')?;
            (name == SESSION_COOKIE && !value.is_empty()).then_some(value)
        })
}
