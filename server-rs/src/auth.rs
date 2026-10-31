//! Mirrors server/app/auth.py's dependency chain
//! (current_user -> require_viewer -> require_operator/require_admin) as
//! axum extractors, plus authenticate_agent for the agent-facing endpoints.
use async_trait::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{Method, StatusCode};
use axum_extra::extract::CookieJar;
use chrono::Utc;
use std::sync::Arc;

use crate::error::ApiError;
use crate::models::{User, UserSession};
use crate::security::{secure_equal, token_hash};
use crate::AppState;

pub const SESSION_COOKIE: &str = "fleetview_session";

/// A signed-in user plus their active session (the session is needed by
/// callers that record it, e.g. the CSRF token or an audit log entry).
pub struct CurrentUser {
    pub user: User,
    pub session: UserSession,
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for CurrentUser {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let unauthorized = || ApiError::unauthorized("Sign in to continue");

        let jar = CookieJar::from_headers(&parts.headers);
        let cookie = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .unwrap_or_default();
        if cookie.is_empty() {
            return Err(unauthorized());
        }

        let hashed = token_hash(&cookie);
        let session = sqlx::query_as::<_, UserSession>(
            "SELECT token_hash, user_id, csrf_token, expires_at FROM user_sessions WHERE token_hash = $1",
        )
        .bind(&hashed)
        .fetch_optional(&state.db)
        .await?;
        let Some(session) = session else {
            return Err(unauthorized());
        };
        if session.expires_at <= Utc::now() {
            return Err(unauthorized());
        }

        let user = sqlx::query_as::<_, User>(
            "SELECT id, username, password_hash, role, active, must_change_password, created_at, last_login_at \
             FROM users WHERE id = $1",
        )
        .bind(&session.user_id)
        .fetch_optional(&state.db)
        .await?;
        let Some(user) = user else {
            return Err(unauthorized());
        };
        if !user.active {
            return Err(unauthorized());
        }

        if !matches!(parts.method, Method::GET | Method::HEAD | Method::OPTIONS) {
            let supplied = parts
                .headers
                .get("X-CSRF-Token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if !secure_equal(supplied, &session.csrf_token) {
                return Err(ApiError::forbidden(
                    "Session verification failed; refresh and try again",
                ));
            }
        }

        Ok(CurrentUser { user, session })
    }
}

/// require_viewer's `None` case is the legacy pre-setup ADMIN_TOKEN
/// bootstrap: valid only before the one-time account setup, never after
/// (checked fresh against auth_control on every call, matching the Python
/// version exactly), and carries no real user to attribute actions to.
pub enum Viewer {
    LegacyBootstrap,
    User(User),
}

impl Viewer {
    pub fn user(&self) -> Option<&User> {
        match self {
            Viewer::LegacyBootstrap => None,
            Viewer::User(user) => Some(user),
        }
    }
}

async fn legacy_bootstrap_ok(state: &AppState, parts: &Parts) -> Result<bool, ApiError> {
    let setup_done: Option<i32> = sqlx::query_scalar("SELECT id FROM auth_control WHERE id = 1")
        .fetch_optional(&state.db)
        .await?;
    if setup_done.is_some() {
        return Ok(false);
    }
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_default();
    if expected.is_empty() {
        return Ok(false);
    }
    let supplied = parts
        .headers
        .get("X-Admin-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    Ok(secure_equal(supplied, &expected))
}

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Viewer {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        if legacy_bootstrap_ok(state, parts).await? {
            return Ok(Viewer::LegacyBootstrap);
        }
        let current = CurrentUser::from_request_parts(parts, state).await?;
        if current.user.must_change_password {
            return Err(ApiError::forbidden(
                "Change your temporary password before continuing",
            ));
        }
        Ok(Viewer::User(current.user))
    }
}

// Not every handler that requires operator-or-above access needs the
// underlying Viewer (e.g. to attribute an audit-log entry), but some do,
// so it's carried here rather than discarded like a unit-struct marker.
#[allow(dead_code)]
pub struct Operator(pub Viewer);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Operator {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let viewer = Viewer::from_request_parts(parts, state).await?;
        if let Some(user) = viewer.user() {
            if user.role != "operator" && user.role != "admin" {
                return Err(ApiError::forbidden("Operator or admin access required"));
            }
        }
        Ok(Operator(viewer))
    }
}

pub struct Admin(pub Viewer);

#[async_trait]
impl FromRequestParts<Arc<AppState>> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let viewer = Viewer::from_request_parts(parts, state).await?;
        if let Some(user) = viewer.user() {
            if user.role != "admin" {
                return Err(ApiError::forbidden("Admin access required"));
            }
        }
        Ok(Admin(viewer))
    }
}

/// The header Caddy's client_auth is configured to set from the verified
/// client certificate's subject (see Caddyfile and client_ca.rs) --
/// present only when the device presented a cert Caddy could verify
/// against the client CA, so its mere absence is never an error: most
/// devices (plain HTTP, or not yet re-enrolled since this feature shipped)
/// simply won't have one, and nothing here requires they do.
const CLIENT_CERT_SUBJECT_HEADER: &str = "x-fleetview-client-cert-subject";

/// Pulls the device ID out of the Caddy-forwarded cert subject header, if
/// present. The cert's whole Subject DN is just "CN=<device id>" (see
/// client_ca.rs -- nothing else is ever set on it), so this is a plain
/// prefix strip, not real DN parsing.
pub fn cert_subject_device_id(headers: &axum::http::HeaderMap) -> Option<String> {
    let raw = headers.get(CLIENT_CERT_SUBJECT_HEADER)?.to_str().ok()?;
    let trimmed = raw.strip_prefix("CN=").unwrap_or(raw).trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Mirrors auth.py's authenticate_agent: Bearer-token auth for the
/// agent-facing endpoints (never a browser session). `cert_subject` is the
/// device ID Caddy says the client certificate on this connection belongs
/// to (via cert_subject_device_id above) -- None whenever no cert was
/// presented or verified, which is the common case and never itself a
/// failure. When a cert *was* presented, though, it must name this same
/// device: a bearer token alone is no longer enough to impersonate a
/// different device over a connection authenticated with someone else's
/// certificate.
pub async fn authenticate_agent_with_cert(
    state: &AppState,
    device_id: &str,
    authorization: &str,
    cert_subject: Option<&str>,
) -> Result<crate::models::Device, ApiError> {
    let unauthorized = || ApiError::new(StatusCode::UNAUTHORIZED, "Invalid agent credentials");
    let Some(token) = authorization.strip_prefix("Bearer ") else {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "Missing agent token",
        ));
    };
    if let Some(subject) = cert_subject {
        if subject != device_id {
            return Err(unauthorized());
        }
    }
    let supplied = token_hash(token.trim());
    let device = sqlx::query_as::<_, crate::models::Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(device) = device else {
        return Err(unauthorized());
    };
    if !secure_equal(&supplied, &device.agent_token_hash) {
        return Err(unauthorized());
    }
    Ok(device)
}
