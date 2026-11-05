use std::{sync::Arc, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use constant_time_eq::constant_time_eq;
use dashmap::DashMap;
use rand::RngCore;
use salvage_protocol::{
    AccountInfo, LoginAttemptResponse, LoginOutcome, QrLoginAttemptResponse, QrPollResponse,
    SessionResponse,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    CoreError, Result,
    accounts::{AccountContext, AccountRegistry, SessionCipher},
    store::ServiceStore,
    telegram::{QrPoll, TelegramFactory, TelegramTransport, TransportLogin},
};

const ATTEMPT_TTL: Duration = Duration::from_secs(10 * 60);
const SESSION_TTL: Duration = Duration::from_secs(30 * 24 * 60 * 60);
const PHONE_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_PHONE_ATTEMPTS: usize = 5;
const MAX_VERIFICATION_FAILURES: u8 = 5;
const MAX_PENDING_LOGINS: usize = 64;

struct LoginAttempt {
    transport: Arc<dyn TelegramTransport>,
    expires_at: std::time::Instant,
    verification_failures: u8,
}

pub struct AuthenticatedAccount {
    pub context: Arc<AccountContext>,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

pub struct IssuedSession {
    pub token: Zeroizing<String>,
    pub response: SessionResponse,
}

pub struct AuthService {
    store: ServiceStore,
    registry: Arc<AccountRegistry>,
    factory: Arc<dyn TelegramFactory>,
    sessions: SessionCipher,
    attempts: DashMap<Uuid, LoginAttempt>,
    qr_attempts: DashMap<Uuid, LoginAttempt>,
    phone_history: DashMap<String, Vec<std::time::Instant>>,
}

impl AuthService {
    pub fn new(
        store: ServiceStore,
        registry: Arc<AccountRegistry>,
        factory: Arc<dyn TelegramFactory>,
        sessions: SessionCipher,
    ) -> Self {
        Self {
            store,
            registry,
            factory,
            sessions,
            attempts: DashMap::new(),
            qr_attempts: DashMap::new(),
            phone_history: DashMap::new(),
        }
    }

    pub async fn begin_phone_login(&self, phone: &str) -> Result<LoginAttemptResponse> {
        let normalized = phone.trim();
        if normalized.len() < 5
            || normalized.len() > 32
            || !normalized
                .chars()
                .all(|c| c.is_ascii_digit() || matches!(c, '+' | ' ' | '-' | '(' | ')'))
        {
            return Err(CoreError::InvalidInput(
                "enter a valid phone number".to_string(),
            ));
        }
        self.cleanup_attempts();
        self.enforce_phone_rate(normalized)?;
        if self.attempts.len() >= MAX_PENDING_LOGINS {
            return Err(CoreError::RateLimited);
        }
        let (transport, attempt) = self.factory.begin_phone_login(normalized).await?;
        let attempt_id = Uuid::new_v4();
        self.attempts.insert(
            attempt_id,
            LoginAttempt {
                transport,
                expires_at: std::time::Instant::now() + ATTEMPT_TTL,
                verification_failures: 0,
            },
        );
        Ok(LoginAttemptResponse {
            attempt_id,
            phone_hint: attempt.phone_hint,
            code_length: attempt.code_length,
            expires_in_seconds: ATTEMPT_TTL.as_secs(),
        })
    }

    pub async fn begin_qr_login(&self) -> Result<QrLoginAttemptResponse> {
        self.cleanup_attempts();
        self.enforce_phone_rate("qr-login")?;
        if self.attempts.len() + self.qr_attempts.len() >= MAX_PENDING_LOGINS {
            return Err(CoreError::RateLimited);
        }
        let (transport, attempt) = self.factory.begin_qr_login().await?;
        let attempt_id = Uuid::new_v4();
        self.qr_attempts.insert(
            attempt_id,
            LoginAttempt {
                transport,
                expires_at: std::time::Instant::now() + ATTEMPT_TTL,
                verification_failures: 0,
            },
        );
        Ok(QrLoginAttemptResponse {
            attempt_id,
            qr_svg: attempt.qr_svg,
            expires_in_seconds: ATTEMPT_TTL.as_secs(),
        })
    }

    pub async fn poll_qr_login(
        &self,
        attempt_id: Uuid,
    ) -> Result<(QrPollResponse, Option<IssuedSession>)> {
        let transport = self
            .qr_attempts
            .get(&attempt_id)
            .ok_or(CoreError::Unauthorized)?
            .transport
            .clone();
        match transport.poll_qr_login().await? {
            QrPoll::Pending { qr_svg } => Ok((
                QrPollResponse {
                    complete: false,
                    qr_svg,
                    session: None,
                },
                None,
            )),
            QrPoll::Ready(TransportLogin::Authenticated) => {
                let issued = self.finish_login(transport).await?;
                self.qr_attempts.remove(&attempt_id);
                Ok((
                    QrPollResponse {
                        complete: true,
                        qr_svg: None,
                        session: Some(issued.response.clone()),
                    },
                    Some(issued),
                ))
            }
            QrPoll::Ready(TransportLogin::PasswordRequired { .. }) => Err(CoreError::Unauthorized),
        }
    }

    pub async fn verify_code(
        &self,
        attempt_id: Uuid,
        code: &str,
    ) -> Result<(LoginOutcome, Option<IssuedSession>)> {
        let transport = self.attempt_transport(attempt_id)?;
        let result = transport.verify_code(code).await;
        if let Err(error) = result {
            if matches!(error, CoreError::Unauthorized) {
                return Err(self.verification_failed(attempt_id));
            }
            return Err(error);
        }
        match result.expect("verification result checked") {
            TransportLogin::PasswordRequired { password_hint } => {
                Ok((LoginOutcome::PasswordRequired { password_hint }, None))
            }
            TransportLogin::Authenticated => {
                let issued = self.finish_login(transport).await?;
                self.attempts.remove(&attempt_id);
                let response = LoginOutcome::Authenticated {
                    session: issued.response.clone(),
                };
                Ok((response, Some(issued)))
            }
        }
    }

    pub async fn verify_password(
        &self,
        attempt_id: Uuid,
        password: &str,
    ) -> Result<(LoginOutcome, Option<IssuedSession>)> {
        let transport = self.attempt_transport(attempt_id)?;
        if let Err(error) = transport.verify_password(password).await {
            if matches!(error, CoreError::Unauthorized) {
                return Err(self.verification_failed(attempt_id));
            }
            return Err(error);
        }
        let issued = self.finish_login(transport).await?;
        self.attempts.remove(&attempt_id);
        let response = LoginOutcome::Authenticated {
            session: issued.response.clone(),
        };
        Ok((response, Some(issued)))
    }

    fn verification_failed(&self, attempt_id: Uuid) -> CoreError {
        let Some(mut attempt) = self.attempts.get_mut(&attempt_id) else {
            return CoreError::Unauthorized;
        };
        attempt.verification_failures = attempt.verification_failures.saturating_add(1);
        let invalidated = attempt.verification_failures >= MAX_VERIFICATION_FAILURES;
        drop(attempt);
        if invalidated {
            self.attempts.remove(&attempt_id);
            CoreError::RateLimited
        } else {
            CoreError::Unauthorized
        }
    }

    fn enforce_phone_rate(&self, phone: &str) -> Result<()> {
        let key = token_hash(phone);
        let now = std::time::Instant::now();
        let mut history = self.phone_history.entry(key).or_default();
        history.retain(|timestamp| now.duration_since(*timestamp) < PHONE_WINDOW);
        if history.len() >= MAX_PHONE_ATTEMPTS {
            return Err(CoreError::RateLimited);
        }
        history.push(now);
        Ok(())
    }

    fn attempt_transport(&self, attempt_id: Uuid) -> Result<Arc<dyn TelegramTransport>> {
        let attempt = self
            .attempts
            .get(&attempt_id)
            .ok_or(CoreError::Unauthorized)?;
        if attempt.expires_at <= std::time::Instant::now() {
            drop(attempt);
            self.attempts.remove(&attempt_id);
            return Err(CoreError::Unauthorized);
        }
        Ok(attempt.transport.clone())
    }

    async fn finish_login(&self, transport: Arc<dyn TelegramTransport>) -> Result<IssuedSession> {
        let user = transport.self_user().ok_or(CoreError::Unauthorized)?;
        let account: AccountInfo = self
            .store
            .find_or_create_account(user.id, &user.display_name)
            .await?
            .into();
        let exported = transport.export_session().await?;
        self.sessions
            .save(&self.registry.account_dir(account.id), &exported)
            .await?;
        self.registry
            .open_with_transport(account.clone(), transport)
            .await?;

        let token = random_token();
        let csrf_token = random_token();
        let expires_at = Utc::now()
            + chrono::Duration::from_std(SESSION_TTL)
                .map_err(|e| CoreError::Internal(e.to_string()))?;
        self.store
            .create_web_session(account.id, &token_hash(&token), &csrf_token, expires_at)
            .await?;
        Ok(IssuedSession {
            token,
            response: SessionResponse {
                account,
                csrf_token: csrf_token.to_string(),
                expires_at,
            },
        })
    }

    pub async fn authenticate(&self, token: &str) -> Result<AuthenticatedAccount> {
        let record = self
            .store
            .find_web_session(&token_hash(token))
            .await?
            .ok_or(CoreError::Unauthorized)?;
        if record.expires_at <= Utc::now() {
            return Err(CoreError::Unauthorized);
        }
        let context = self.registry.open(record.account()).await?;
        Ok(AuthenticatedAccount {
            context,
            csrf_token: record.csrf_token,
            expires_at: record.expires_at,
        })
    }

    pub fn validate_csrf(
        authenticated: &AuthenticatedAccount,
        supplied: Option<&str>,
    ) -> Result<()> {
        let supplied = supplied.ok_or(CoreError::Unauthorized)?;
        if constant_time_eq(authenticated.csrf_token.as_bytes(), supplied.as_bytes()) {
            Ok(())
        } else {
            Err(CoreError::Unauthorized)
        }
    }

    pub fn session_response(authenticated: &AuthenticatedAccount) -> SessionResponse {
        SessionResponse {
            account: authenticated.context.info().clone(),
            csrf_token: authenticated.csrf_token.clone(),
            expires_at: authenticated.expires_at,
        }
    }

    pub async fn logout(&self, token: &str) -> Result<()> {
        let authenticated = self.authenticate(token).await?;
        let account_id = authenticated.context.info().id;
        self.store.revoke_web_sessions(account_id).await?;
        self.registry.revoke(account_id).await
    }

    pub async fn cleanup(&self) -> Result<()> {
        self.cleanup_attempts();
        self.store.delete_expired_sessions().await
    }

    fn cleanup_attempts(&self) {
        let now = std::time::Instant::now();
        self.attempts.retain(|_, attempt| attempt.expires_at > now);
        self.qr_attempts
            .retain(|_, attempt| attempt.expires_at > now);
        self.phone_history.retain(|_, history| {
            history.retain(|timestamp| now.duration_since(*timestamp) < PHONE_WINDOW);
            !history.is_empty()
        });
    }
}

fn random_token() -> Zeroizing<String> {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes))
}

fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
