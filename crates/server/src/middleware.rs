use std::{path::PathBuf, sync::Arc};

use axum::{
    Json,
    extract::{Request, State},
    http::{HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use salvage_backend_core::{CoreError, Result};
use salvage_protocol::ErrorResponse;
use sha2::{Digest, Sha256};

pub fn content_security_policy(index_html: &str) -> Result<Arc<str>> {
    const OPEN: &str = "<script type=\"module\">";
    let start = index_html
        .find(OPEN)
        .map(|offset| offset + OPEN.len())
        .ok_or_else(|| {
            CoreError::InvalidInput("built index.html has no Trunk bootstrap script".to_string())
        })?;
    let end = index_html[start..]
        .find("</script>")
        .map(|offset| start + offset)
        .ok_or_else(|| {
            CoreError::InvalidInput(
                "built index.html has an incomplete Trunk bootstrap".to_string(),
            )
        })?;
    let digest = STANDARD.encode(Sha256::digest(&index_html.as_bytes()[start..end]));
    Ok(Arc::from(format!(
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-{digest}'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )))
}

#[derive(Clone)]
pub struct SecurityHeaderState {
    index_html: Arc<PathBuf>,
    fallback_csp: Arc<str>,
}

impl SecurityHeaderState {
    pub fn new(index_html: PathBuf, fallback_csp: Arc<str>) -> Self {
        Self {
            index_html: Arc::new(index_html),
            fallback_csp,
        }
    }
}

#[derive(Clone)]
pub struct OriginPolicy {
    primary: String,
    allow_loopback: bool,
}

impl OriginPolicy {
    pub fn new(primary: String, allow_loopback: bool) -> Self {
        Self {
            primary,
            allow_loopback,
        }
    }

    fn allows(&self, origin: Option<&str>) -> bool {
        match origin {
            Some(origin) if origin == self.primary => true,
            Some(origin) if self.allow_loopback => is_loopback_origin(origin),
            _ => false,
        }
    }
}

fn is_loopback_origin(origin: &str) -> bool {
    let Ok(uri) = origin.parse::<axum::http::Uri>() else {
        return false;
    };
    if uri.scheme_str() != Some("http") {
        return false;
    }
    uri.authority().is_some_and(|authority| {
        matches!(
            authority.host(),
            "localhost" | "127.0.0.1" | "::1" | "[::1]"
        )
    })
}

pub async fn require_origin(
    State(policy): State<OriginPolicy>,
    request: Request,
    next: Next,
) -> Response {
    if matches!(request.method(), &Method::GET | &Method::HEAD) {
        return next.run(request).await;
    }
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok());
    if !policy.allows(origin) {
        return api_error(
            StatusCode::FORBIDDEN,
            "origin_rejected",
            "the request origin is not allowed",
        );
    }
    next.run(request).await
}

pub async fn security_headers(
    State(state): State<SecurityHeaderState>,
    request: Request,
    next: Next,
) -> Response {
    let sensitive = request.uri().path().starts_with("/api/")
        || request.uri().path().starts_with("/s/")
        || request.uri().path() == "/crypto-worker.json";
    let mut response = next.run(request).await;
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let inline_pdf = content_type.as_deref() == Some("application/pdf")
        && response
            .headers()
            .get(header::CONTENT_DISPOSITION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("inline"));
    let html_response = content_type
        .as_deref()
        .is_some_and(|value| value.starts_with("text/html"));
    let csp = if html_response {
        match tokio::fs::read_to_string(state.index_html.as_ref()).await {
            Ok(index_html) => content_security_policy(&index_html).unwrap_or_else(|error| {
                tracing::warn!(%error, "could not refresh the browser bootstrap CSP hash");
                state.fallback_csp.clone()
            }),
            Err(error) => {
                tracing::warn!(%error, "could not read index.html for the browser CSP hash");
                state.fallback_csp.clone()
            }
        }
    } else {
        state.fallback_csp.clone()
    };
    let headers = response.headers_mut();
    if inline_pdf {
        insert(
            headers,
            header::CONTENT_SECURITY_POLICY,
            &csp.replace("frame-ancestors 'none'", "frame-ancestors 'self'"),
        );
        insert(headers, header::X_FRAME_OPTIONS, "SAMEORIGIN");
    } else {
        insert(headers, header::CONTENT_SECURITY_POLICY, csp.as_ref());
        insert(headers, header::X_FRAME_OPTIONS, "DENY");
    }
    insert(headers, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    insert(headers, header::REFERRER_POLICY, "no-referrer");
    insert(
        headers,
        header::HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()",
    );
    if sensitive {
        insert(headers, header::CACHE_CONTROL, "no-store");
    }
    response
}

fn insert(headers: &mut header::HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

fn api_error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            code: code.to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}
