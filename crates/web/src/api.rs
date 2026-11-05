use serde::Serialize;
use serde::de::DeserializeOwned;

use gloo_net::http::{Request, RequestBuilder, Response};
use js_sys::Uint8Array;
use salvage_protocol::{
    AddBotTokenRequest, BotTokenInfo, CloudPasswordRequest, CompleteUploadResponse,
    CreateFolderRequest, CreateShareRequest, CreateUploadRequest, CreatedShare, DownloadResponse,
    ErrorResponse, FilePage, Folder, LoginAttemptResponse, LoginOutcome, PhoneLoginRequest,
    QrLoginAttemptResponse, QrPollResponse, RenameFolderRequest, SessionResponse, Share, Transfer,
    UploadResponse, VerifyCodeRequest,
};
use uuid::Uuid;
use web_sys::{AbortSignal, RequestCredentials};

#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: Option<u16>,
    pub message: String,
}

impl ApiError {
    pub fn is_unauthorized(&self) -> bool {
        self.status == Some(401)
    }

    pub fn is_conflict(&self) -> bool {
        self.status == Some(409)
    }

    fn transport(message: impl Into<String>) -> Self {
        Self {
            status: None,
            message: message.into(),
        }
    }
}

async fn send(builder: RequestBuilder) -> Result<Response, ApiError> {
    builder
        .credentials(RequestCredentials::SameOrigin)
        .send()
        .await
        .map_err(|error| {
            ApiError::transport(format!(
                "We couldn’t reach Salvage Cloud. Check your connection and try again. ({error})"
            ))
        })
}

async fn send_request(request: Request) -> Result<Response, ApiError> {
    request.send().await.map_err(|error| {
        ApiError::transport(format!(
            "We couldn’t reach Salvage Cloud. Check your connection and try again. ({error})"
        ))
    })
}

async fn decode<T: DeserializeOwned>(response: Response) -> Result<T, ApiError> {
    if response.ok() {
        response.json::<T>().await.map_err(|error| {
            ApiError::transport(format!(
                "The server returned an unreadable response. ({error})"
            ))
        })
    } else {
        Err(decode_error(response).await)
    }
}

async fn decode_error(response: Response) -> ApiError {
    let status = response.status();
    match response.json::<ErrorResponse>().await {
        Ok(error) => ApiError {
            status: Some(status),
            message: error.message,
        },
        Err(_) => ApiError {
            status: Some(status),
            message: match status {
                401 => "Your session has expired. Please sign in again.".to_owned(),
                403 => "This action isn’t allowed for the current session.".to_owned(),
                404 => {
                    "That item could not be found. It may have been moved or deleted.".to_owned()
                }
                429 => "Too many attempts. Please wait a moment and try again.".to_owned(),
                500..=599 => {
                    "Salvage Cloud is having trouble right now. Please try again.".to_owned()
                }
                _ => format!("The request couldn’t be completed (HTTP {status})."),
            },
        },
    }
}

fn json_body<T: Serialize>(builder: RequestBuilder, body: &T) -> Result<Request, ApiError> {
    let body = serde_json::to_string(body)
        .map_err(|error| ApiError::transport(format!("Couldn’t prepare the request. ({error})")))?;
    builder
        .header("Content-Type", "application/json")
        .credentials(RequestCredentials::SameOrigin)
        .body(body)
        .map_err(|error| ApiError::transport(format!("Couldn’t prepare the request. ({error})")))
}

fn csrf(builder: RequestBuilder, csrf_token: &str) -> RequestBuilder {
    builder.header("X-CSRF-Token", csrf_token)
}

fn query_string(entries: &[(&str, &str)]) -> String {
    let params = web_sys::UrlSearchParams::new().expect("URLSearchParams is available in browsers");
    for (key, value) in entries {
        params.append(key, value);
    }
    params.to_string().as_string().unwrap_or_default()
}

pub async fn get_session() -> Result<Option<SessionResponse>, ApiError> {
    let response = send(Request::get("/api/v1/auth/session")).await?;
    if response.status() == 401 {
        Ok(None)
    } else {
        decode(response).await.map(Some)
    }
}

pub async fn start_phone_login(phone: &str) -> Result<LoginAttemptResponse, ApiError> {
    let request = json_body(
        Request::post("/api/v1/auth/phone"),
        &PhoneLoginRequest {
            phone: phone.to_owned(),
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn start_qr_login() -> Result<QrLoginAttemptResponse, ApiError> {
    decode(send(Request::post("/api/v1/auth/qr")).await?).await
}

pub async fn poll_qr_login(attempt_id: Uuid) -> Result<QrPollResponse, ApiError> {
    decode(send(Request::post(&format!("/api/v1/auth/qr/{attempt_id}"))).await?).await
}

pub async fn verify_code(attempt_id: Uuid, code: &str) -> Result<LoginOutcome, ApiError> {
    let request = json_body(
        Request::post("/api/v1/auth/code"),
        &VerifyCodeRequest {
            attempt_id,
            code: code.to_owned(),
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn verify_password(attempt_id: Uuid, password: &str) -> Result<LoginOutcome, ApiError> {
    let request = json_body(
        Request::post("/api/v1/auth/password"),
        &CloudPasswordRequest {
            attempt_id,
            password: password.to_owned(),
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn logout(csrf_token: &str) -> Result<(), ApiError> {
    let response = send(csrf(Request::post("/api/v1/auth/logout"), csrf_token)).await?;
    if response.ok() {
        Ok(())
    } else {
        Err(decode_error(response).await)
    }
}

pub async fn list_folders(parent_id: Option<&str>) -> Result<Vec<Folder>, ApiError> {
    let path = match parent_id {
        Some(parent_id) => format!(
            "/api/v1/folders?{}",
            query_string(&[("parent_id", parent_id)])
        ),
        None => "/api/v1/folders".to_owned(),
    };
    decode(send(Request::get(&path)).await?).await
}

pub async fn create_folder(
    name: &str,
    parent_id: Option<&str>,
    csrf_token: &str,
) -> Result<Folder, ApiError> {
    let request = json_body(
        csrf(Request::post("/api/v1/folders"), csrf_token),
        &CreateFolderRequest {
            name: name.to_owned(),
            parent_id: parent_id.map(str::to_owned),
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn rename_folder(id: &str, name: &str, csrf_token: &str) -> Result<Folder, ApiError> {
    let request = json_body(
        csrf(Request::patch(&format!("/api/v1/folders/{id}")), csrf_token),
        &RenameFolderRequest {
            name: name.to_owned(),
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn activate_folder(id: &str, csrf_token: &str) -> Result<Folder, ApiError> {
    let response = send(csrf(
        Request::post(&format!("/api/v1/channels/{id}/activate")),
        csrf_token,
    ))
    .await?;
    decode(response).await
}

pub async fn delete_folder(id: &str, csrf_token: &str) -> Result<(), ApiError> {
    let response = send(csrf(
        Request::delete(&format!("/api/v1/folders/{id}")),
        csrf_token,
    ))
    .await?;
    if response.ok() {
        Ok(())
    } else {
        Err(decode_error(response).await)
    }
}

pub async fn list_files(
    folder_id: Option<&str>,
    query: Option<&str>,
) -> Result<FilePage, ApiError> {
    let mut entries = Vec::new();
    if let Some(folder_id) = folder_id {
        entries.push(("folder_id", folder_id));
    }
    if let Some(query) = query.filter(|query| !query.is_empty()) {
        entries.push(("q", query));
    }
    let path = if entries.is_empty() {
        "/api/v1/files".to_owned()
    } else {
        format!("/api/v1/files?{}", query_string(&entries))
    };
    decode(send(Request::get(&path)).await?).await
}

pub async fn list_transfers() -> Result<Vec<Transfer>, ApiError> {
    decode(send(Request::get("/api/v1/transfers")).await?).await
}

pub async fn create_upload(
    request: &CreateUploadRequest,
    csrf_token: &str,
    signal: Option<&AbortSignal>,
) -> Result<UploadResponse, ApiError> {
    let request = json_body(
        csrf(Request::post("/api/v1/transfers/uploads"), csrf_token).abort_signal(signal),
        request,
    )?;
    decode(send_request(request).await?).await
}

pub async fn append_upload_chunk(
    id: Uuid,
    offset: u64,
    bytes: Uint8Array,
    csrf_token: &str,
    signal: Option<&AbortSignal>,
) -> Result<UploadResponse, ApiError> {
    let request = csrf(
        Request::put(&format!("/api/v1/transfers/uploads/{id}/content")),
        csrf_token,
    )
    .header("Content-Type", "application/octet-stream")
    .header("X-Upload-Offset", &offset.to_string())
    .credentials(RequestCredentials::SameOrigin)
    .abort_signal(signal)
    .body(bytes)
    .map_err(|error| {
        ApiError::transport(format!("Couldn’t prepare the upload chunk. ({error})"))
    })?;
    decode(send_request(request).await?).await
}

pub async fn complete_upload(
    id: Uuid,
    csrf_token: &str,
    signal: Option<&AbortSignal>,
) -> Result<CompleteUploadResponse, ApiError> {
    let response = send(
        csrf(
            Request::post(&format!("/api/v1/transfers/uploads/{id}/complete")),
            csrf_token,
        )
        .abort_signal(signal),
    )
    .await?;
    decode(response).await
}

pub async fn delete_file(id: &str, csrf_token: &str) -> Result<(), ApiError> {
    let response = send(csrf(
        Request::delete(&format!("/api/v1/files/{id}")),
        csrf_token,
    ))
    .await?;
    if response.ok() {
        Ok(())
    } else {
        Err(decode_error(response).await)
    }
}

pub async fn prepare_download(
    file_id: &str,
    csrf_token: &str,
) -> Result<DownloadResponse, ApiError> {
    let request = csrf(
        Request::post(&format!("/api/v1/transfers/downloads/{file_id}")),
        csrf_token,
    );
    decode(send(request).await?).await
}

pub async fn cancel_transfer(id: Uuid, csrf_token: &str) -> Result<Transfer, ApiError> {
    let response = send(csrf(
        Request::delete(&format!("/api/v1/transfers/{id}")),
        csrf_token,
    ))
    .await?;
    decode(response).await
}

pub async fn get_inline_text(url: &str) -> Result<String, ApiError> {
    let response = send(Request::get(url)).await?;
    if response.ok() {
        response.text().await.map_err(|error| {
            ApiError::transport(format!("The text preview couldn’t be read. ({error})"))
        })
    } else {
        Err(decode_error(response).await)
    }
}

pub async fn list_shares(file_id: &str) -> Result<Vec<Share>, ApiError> {
    decode(send(Request::get(&format!("/api/v1/files/{file_id}/shares"))).await?).await
}

pub async fn create_share(
    file_id: &str,
    expires_in_hours: u16,
    csrf_token: &str,
) -> Result<CreatedShare, ApiError> {
    let request = json_body(
        csrf(
            Request::post(&format!("/api/v1/files/{file_id}/shares")),
            csrf_token,
        ),
        &CreateShareRequest {
            expires_in_hours: Some(expires_in_hours),
            expires_in_seconds: None,
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn list_bots() -> Result<Vec<BotTokenInfo>, ApiError> {
    decode(send(Request::get("/api/v1/bots")).await?).await
}

pub async fn add_bot(label: &str, token: &str, csrf_token: &str) -> Result<BotTokenInfo, ApiError> {
    let request = json_body(
        csrf(Request::post("/api/v1/bots"), csrf_token),
        &AddBotTokenRequest {
            label: label.to_owned(),
            token: token.to_owned(),
        },
    )?;
    decode(send_request(request).await?).await
}

pub async fn delete_bot(id: Uuid, csrf_token: &str) -> Result<(), ApiError> {
    let response = send(csrf(
        Request::delete(&format!("/api/v1/bots/{id}")),
        csrf_token,
    ))
    .await?;
    if response.ok() {
        Ok(())
    } else {
        Err(decode_error(response).await)
    }
}

pub async fn provision_bot(id: Uuid, csrf_token: &str) -> Result<(), ApiError> {
    let response = send(csrf(
        Request::post(&format!("/api/v1/bots/{id}/provision")),
        csrf_token,
    ))
    .await?;
    if response.ok() {
        Ok(())
    } else {
        Err(decode_error(response).await)
    }
}

pub async fn revoke_share(id: Uuid, csrf_token: &str) -> Result<Share, ApiError> {
    let response = send(csrf(
        Request::delete(&format!("/api/v1/shares/{id}")),
        csrf_token,
    ))
    .await?;
    decode(response).await
}
