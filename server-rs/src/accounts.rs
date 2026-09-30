//! Mirrors server/app/accounts.py's setup/login/me/logout slice (the rest
//! -- user CRUD, password change, full throttling refinement -- follows in
//! a later increment; this one exists to prove the auth chain in auth.rs
//! works end-to-end against a real login flow).
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use crate::auth::{CurrentUser, SESSION_COOKIE};
use crate::error::ApiError;
use crate::security::{new_agent_token, password_hash, secure_equal, token_hash, verify_password};
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/setup", post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/logout", post(logout))
}

/// A random password's hash, computed once at first use and reused for
/// every login against an unknown username -- so verify_password's
/// (deliberately slow) PBKDF2 work always runs, and how long a login
/// request takes never reveals whether the username exists.
fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| password_hash(&new_agent_token()))
}

/// Mirrors accounts.py's browser_write dependency: every state-changing
/// auth endpoint requires this custom header (forces a CORS preflight for
/// cross-origin browser requests, since this app enables no CORS) and
/// rejects cross-site requests outright.
fn require_browser_write(headers: &HeaderMap) -> Result<(), ApiError> {
    if headers
        .get("X-FleetView-Request")
        .and_then(|v| v.to_str().ok())
        != Some("1")
    {
        return Err(ApiError::forbidden("Request verification required"));
    }
    if headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site") {
        return Err(ApiError::forbidden("Cross-site requests are not allowed"));
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        let host = headers
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let origin_ok = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .map(|rest| rest == host)
            .unwrap_or(false);
        if !origin_ok {
            return Err(ApiError::forbidden("Cross-origin requests are not allowed"));
        }
    }
    Ok(())
}

/// Mirrors accounts.py's throttle(): persistent, atomic, 15-minute-window
/// counters shared by every worker via the database (not in-process
/// state), keyed by both source IP and account so one abusive peer can't
/// lock out everyone else's login attempts.
async fn throttle(state: &AppState, peer: &str, username: &str) -> Result<(), ApiError> {
    let now = Utc::now();
    let window = now.timestamp() / 900;
    sqlx::query("DELETE FROM login_throttles WHERE expires_at < $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    let mut denied = false;
    for (scope, limit) in [
        (format!("peer:{peer}:{window}"), 60i32),
        (format!("account:{username}:{window}"), 10i32),
    ] {
        let key = token_hash(&scope);
        let expires = now + Duration::minutes(30);
        sqlx::query(
            "INSERT INTO login_throttles (key, attempts, expires_at) VALUES ($1, 0, $2) \
             ON CONFLICT (key) DO NOTHING",
        )
        .bind(&key)
        .bind(expires)
        .execute(&state.db)
        .await?;
        let attempts: i32 = sqlx::query_scalar(
            "UPDATE login_throttles SET attempts = attempts + 1 WHERE key = $1 RETURNING attempts",
        )
        .bind(&key)
        .fetch_one(&state.db)
        .await?;
        denied = denied || attempts > limit;
    }
    if denied {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many attempts. Try again in 15 minutes.",
        ));
    }
    Ok(())
}

async fn audit(state: &AppState, actor: &str, action: &str, target: &str, details: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO account_audit (actor, action, target, details) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(details)
        .execute(&state.db)
        .await?;
    Ok(())
}

#[derive(Serialize)]
struct UserView {
    id: String,
    username: String,
    role: String,
    active: bool,
    must_change_password: bool,
    created_at: chrono::DateTime<Utc>,
    last_login_at: Option<chrono::DateTime<Utc>>,
}

impl From<&crate::models::User> for UserView {
    fn from(u: &crate::models::User) -> Self {
        Self {
            id: u.id.clone(),
            username: u.username.clone(),
            role: u.role.clone(),
            active: u.active,
            must_change_password: u.must_change_password,
            created_at: u.created_at,
            last_login_at: u.last_login_at,
        }
    }
}

/// Starts a session for `user`: rotates out any expired sessions and the
/// caller's own stale cookie (if any), inserts a fresh one, and returns the
/// jar with the new cookie plus the JSON body the dashboard expects.
async fn start_session(
    state: &AppState,
    jar: CookieJar,
    is_https: bool,
    user: &crate::models::User,
) -> Result<(CookieJar, Json<serde_json::Value>), ApiError> {
    let raw = new_agent_token();
    let csrf = new_agent_token();
    let now = Utc::now();

    sqlx::query("DELETE FROM user_sessions WHERE expires_at <= $1")
        .bind(now)
        .execute(&state.db)
        .await?;
    if let Some(old) = jar.get(SESSION_COOKIE) {
        sqlx::query("DELETE FROM user_sessions WHERE token_hash = $1")
            .bind(token_hash(old.value()))
            .execute(&state.db)
            .await?;
    }
    sqlx::query(
        "INSERT INTO user_sessions (token_hash, user_id, csrf_token, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(token_hash(&raw))
    .bind(&user.id)
    .bind(&csrf)
    .bind(now + Duration::hours(12))
    .execute(&state.db)
    .await?;
    sqlx::query("UPDATE users SET last_login_at = $1 WHERE id = $2")
        .bind(now)
        .bind(&user.id)
        .execute(&state.db)
        .await?;

    let secure = is_https
        || std::env::var("FLEETVIEW_COOKIE_SECURE").unwrap_or_default().to_lowercase() == "true";
    let cookie = Cookie::build((SESSION_COOKIE, raw))
        .max_age(time::Duration::seconds(43200))
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .path("/")
        .build();
    let jar = jar.add(cookie);
    // last_login_at just changed in the UPDATE above; reflect that in the
    // response instead of the caller's now-stale copy of the row.
    let mut view = UserView::from(user);
    view.last_login_at = Some(now);
    let body = Json(json!({ "user": view, "csrf_token": csrf }));
    Ok((jar, body))
}

async fn auth_status(State(state): State<Arc<AppState>>) -> Result<Json<serde_json::Value>, ApiError> {
    let setup_done: Option<i32> = sqlx::query_scalar("SELECT id FROM auth_control WHERE id = 1")
        .fetch_optional(&state.db)
        .await?;
    Ok(Json(json!({ "setup_required": setup_done.is_none() })))
}

#[derive(Deserialize)]
struct SetupPayload {
    admin_token: String,
    username: String,
    password: String,
}

fn valid_username(username: &str) -> bool {
    if username.is_empty() || username.len() > 64 {
        return false;
    }
    let mut chars = username.chars();
    let Some(first) = chars.next() else { return false };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

async fn setup(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<SetupPayload>,
) -> Result<impl IntoResponse, ApiError> {
    require_browser_write(&headers)?;
    let peer = client_ip(&headers);
    throttle(&state, &peer, "setup").await?;

    if payload.username.is_empty() || payload.password.len() < 12 || payload.password.len() > 128 {
        return Err(ApiError::bad_request("Invalid username or password"));
    }
    let username = payload.username.to_lowercase();
    if !valid_username(&username) {
        return Err(ApiError::bad_request("Invalid username"));
    }

    let setup_done: Option<i32> = sqlx::query_scalar("SELECT id FROM auth_control WHERE id = 1")
        .fetch_optional(&state.db)
        .await?;
    if setup_done.is_some() {
        return Err(ApiError::conflict("Account setup is already complete"));
    }
    let expected = std::env::var("ADMIN_TOKEN").unwrap_or_default();
    if expected.is_empty() || !secure_equal(&payload.admin_token, &expected) {
        return Err(ApiError::unauthorized("Setup authorization failed"));
    }

    let mut tx = state.db.begin().await?;
    let inserted = sqlx::query("INSERT INTO auth_control (id) VALUES (1) ON CONFLICT DO NOTHING")
        .execute(&mut *tx)
        .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("Account setup is already complete"));
    }
    let user_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, active, must_change_password) \
         VALUES ($1, $2, $3, 'admin', true, false)",
    )
    .bind(&user_id)
    .bind(&username)
    .bind(password_hash(&payload.password))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    audit(&state, &username, "setup", &username, "First administrator created").await?;

    let user = fetch_user_by_id(&state, &user_id).await?;
    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https");
    let (jar, body) = start_session(&state, jar, is_https, &user).await?;
    Ok((StatusCode::CREATED, jar, body))
}

#[derive(Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

async fn login(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    jar: CookieJar,
    Json(payload): Json<LoginPayload>,
) -> Result<impl IntoResponse, ApiError> {
    require_browser_write(&headers)?;
    let peer = client_ip(&headers);
    let username = payload.username.to_lowercase();
    throttle(&state, &peer, &username).await?;

    let user = sqlx::query_as::<_, crate::models::User>(
        "SELECT id, username, password_hash, role, active, must_change_password, created_at, last_login_at \
         FROM users WHERE username = $1 FOR UPDATE",
    )
    .bind(&username)
    .fetch_optional(&state.db)
    .await?;

    // Always run verify_password, even for an unknown username (against
    // the fixed dummy hash), so response timing never leaks whether the
    // account exists.
    let hash_to_check = user
        .as_ref()
        .map(|u| u.password_hash.clone())
        .unwrap_or_else(|| dummy_hash().to_string());
    let valid = verify_password(&payload.password, &hash_to_check);

    let Some(user) = user else {
        return Err(ApiError::unauthorized("Invalid username or password"));
    };
    if !valid || !user.active {
        return Err(ApiError::unauthorized("Invalid username or password"));
    }

    let is_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        == Some("https");
    let (jar, body) = start_session(&state, jar, is_https, &user).await?;
    Ok((jar, body))
}

async fn me(current: CurrentUser) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert("Cache-Control", "no-store".parse().unwrap());
    (
        headers,
        Json(json!({ "user": UserView::from(&current.user), "csrf_token": current.session.csrf_token })),
    )
}

async fn logout(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    jar: CookieJar,
) -> Result<impl IntoResponse, ApiError> {
    sqlx::query("DELETE FROM user_sessions WHERE token_hash = $1")
        .bind(&current.session.token_hash)
        .execute(&state.db)
        .await?;
    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    Ok((StatusCode::NO_CONTENT, jar))
}

async fn fetch_user_by_id(state: &AppState, id: &str) -> Result<crate::models::User, ApiError> {
    sqlx::query_as::<_, crate::models::User>(
        "SELECT id, username, password_hash, role, active, must_change_password, created_at, last_login_at \
         FROM users WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::from)
}

/// No `TRUSTED_PROXY_COUNT`-based real-IP resolution yet (see
/// deployment.py's equivalent in the Python server, ported alongside the
/// rest of that file) -- this is only used to key throttling, and a wrong
/// value there only affects a rate limit, not authorization.
fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .unwrap_or("unknown")
        .trim()
        .to_string()
}
