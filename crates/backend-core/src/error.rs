use thiserror::Error;

pub type Result<T> = std::result::Result<T, CoreError>;

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("invalid request: {0}")]
    InvalidInput(String),
    #[error("authentication is required or the supplied credentials are invalid")]
    Unauthorized,
    #[error("the requested object was not found")]
    NotFound,
    #[error("the request conflicts with current state: {0}")]
    Conflict(String),
    #[error("the Telegram service is unavailable: {0}")]
    Unavailable(String),
    #[error("too many authentication attempts; wait before trying again")]
    RateLimited,
    #[error("persistent storage failed")]
    Storage(#[source] sqlite::Error),
    #[error("an internal operation failed without exposing sensitive details")]
    Internal(String),
}

impl From<sqlite::Error> for CoreError {
    fn from(value: sqlite::Error) -> Self {
        Self::Storage(value)
    }
}

impl From<std::io::Error> for CoreError {
    fn from(_value: std::io::Error) -> Self {
        Self::Internal("I/O operation failed".to_string())
    }
}
