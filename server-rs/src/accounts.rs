//! Mirrors server/app/accounts.py in full: setup/login/me/logout, password
//! change, and admin user management + the recent-audit-log endpoint.
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use crate::auth::{Admin, CurrentUser, SESSION_COOKIE};
use crate::error::ApiError;
use crate::security::{new_agent_token, password_hash, secure_equal, token_hash, verify_password, verify_password_async};
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/auth/status", get(auth_status))
        .route("/api/v1/auth/setup", post(setup))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/me", get(me))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/password", post(change_password))
        .route("/api/v1/admin/users", get(list_users).post(create_user))
        .route("/api/v1/admin/users/:id", put(edit_user))
        .route("/api/v1/admin/users/audit/recent", get(audit_history))
}

/// account_admin in the Python server: like Admin, but the legacy
/// pre-setup token bootstrap cannot create/edit arbitrary users (there's
/// no real actor to attribute the action to).
fn require_real_admin(admin: &Admin) -> Result<&crate::models::User, ApiError> {
    admin
        .0
        .user()
        .ok_or_else(|| ApiError::forbidden("Complete account setup first"))
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
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, $2, $3, $4, now())")
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
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    Json(payload): Json<SetupPayload>,
) -> Result<impl IntoResponse, ApiError> {
    require_browser_write(&headers)?;
    let peer = client_ip(&headers, peer_addr.ip());
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
        "INSERT INTO users (id, username, password_hash, role, active, must_change_password, created_at) \
         VALUES ($1, $2, $3, 'admin', true, false, now())",
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
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    Json(payload): Json<LoginPayload>,
) -> Result<impl IntoResponse, ApiError> {
    require_browser_write(&headers)?;
    let peer = client_ip(&headers, peer_addr.ip());
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
    // Off the async executor: 600,000 PBKDF2 iterations is tens of
    // milliseconds of pure CPU work, long enough on a hot login endpoint
    // (every attempt, including failed ones against the dummy hash above)
    // to starve other requests on the same worker thread.
    let valid = verify_password_async(payload.password.clone(), hash_to_check).await;

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

/// Mirrors uvicorn's `--forwarded-allow-ips` trust model (see
/// docker-compose.yml's `command:` for the Python server): X-Forwarded-For
/// is honored only when the request's actual TCP peer is itself a trusted
/// proxy (Caddy, or localhost), so an external client can't simply forge
/// the header to spoof a different throttle key and dodge the rate limit.
/// Untrusted requests are keyed by their real socket address instead.
fn client_ip(headers: &HeaderMap, peer: std::net::IpAddr) -> String {
    if trusted_proxy_ips().contains(&peer) {
        if let Some(forwarded) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(candidate) = forwarded.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                return candidate.to_string();
            }
        }
    }
    peer.to_string()
}

fn trusted_proxy_ips() -> Vec<std::net::IpAddr> {
    std::env::var("FORWARDED_ALLOW_IPS")
        .unwrap_or_else(|_| "127.0.0.1".to_string())
        .split(',')
        .filter_map(|s| s.trim().parse().ok())
        .collect()
}

#[derive(Deserialize)]
struct ChangePasswordPayload {
    current_password: String,
    new_password: String,
}

async fn change_password(
    State(state): State<Arc<AppState>>,
    current: CurrentUser,
    headers: HeaderMap,
    ConnectInfo(peer_addr): ConnectInfo<std::net::SocketAddr>,
    jar: CookieJar,
    Json(payload): Json<ChangePasswordPayload>,
) -> Result<impl IntoResponse, ApiError> {
    require_browser_write(&headers)?;
    if payload.new_password.len() < 12 || payload.new_password.len() > 128 {
        return Err(ApiError::bad_request("New password must be at least 12 characters"));
    }
    let peer = client_ip(&headers, peer_addr.ip());
    throttle(&state, &peer, &format!("password:{}", current.user.id)).await?;

    // Re-read under lock: the hash used above (from the extractor) could
    // already be stale if a concurrent request changed it.
    let mut tx = state.db.begin().await?;
    let password_hash_row: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1 FOR UPDATE")
            .bind(&current.user.id)
            .fetch_one(&mut *tx)
            .await?;
    if !verify_password(&payload.current_password, &password_hash_row) {
        return Err(ApiError::bad_request("Current password is incorrect"));
    }
    if payload.current_password == payload.new_password {
        return Err(ApiError::bad_request("Choose a different password"));
    }
    let new_hash = password_hash(&payload.new_password);
    sqlx::query("UPDATE users SET password_hash = $1, must_change_password = false WHERE id = $2")
        .bind(&new_hash)
        .bind(&current.user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
        .bind(&current.user.id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, 'password_changed', $1, '', now())")
        .bind(&current.user.username)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let jar = jar.remove(Cookie::from(SESSION_COOKIE));
    Ok((StatusCode::NO_CONTENT, jar))
}

async fn list_users(State(state): State<Arc<AppState>>, admin: Admin) -> Result<Json<Vec<UserView>>, ApiError> {
    require_real_admin(&admin)?;
    let users = sqlx::query_as::<_, crate::models::User>(
        "SELECT id, username, password_hash, role, active, must_change_password, created_at, last_login_at \
         FROM users ORDER BY username",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(users.iter().map(UserView::from).collect()))
}

#[derive(Deserialize)]
struct CreateUserPayload {
    username: String,
    password: String,
    #[serde(default = "default_role")]
    role: String,
}

fn default_role() -> String {
    "viewer".to_string()
}

fn valid_role(role: &str) -> bool {
    matches!(role, "admin" | "operator" | "viewer")
}

async fn create_user(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Json(payload): Json<CreateUserPayload>,
) -> Result<impl IntoResponse, ApiError> {
    let actor = require_real_admin(&admin)?;
    if payload.password.len() < 12 || payload.password.len() > 128 {
        return Err(ApiError::bad_request("Password must be at least 12 characters"));
    }
    let username = payload.username.to_lowercase();
    if !valid_username(&username) {
        return Err(ApiError::bad_request("Invalid username"));
    }
    if !valid_role(&payload.role) {
        return Err(ApiError::bad_request("Invalid role"));
    }

    let mut tx = state.db.begin().await?;
    // Lock against concurrent admin edits the same way the Python server
    // does (SELECT ... FOR UPDATE on the auth_control singleton), then
    // re-verify the actor is still an active admin under that lock.
    sqlx::query("SELECT id FROM auth_control WHERE id = 1 FOR UPDATE")
        .fetch_optional(&mut *tx)
        .await?;
    let (actor_active, actor_role): (bool, String) =
        sqlx::query_as("SELECT active, role FROM users WHERE id = $1")
            .bind(&actor.id)
            .fetch_one(&mut *tx)
            .await?;
    if !actor_active || actor_role != "admin" {
        return Err(ApiError::forbidden("Admin access required"));
    }

    let user_id = Uuid::new_v4().to_string();
    let inserted = sqlx::query(
        "INSERT INTO users (id, username, password_hash, role, active, must_change_password, created_at) \
         VALUES ($1, $2, $3, $4, true, true, now()) ON CONFLICT (username) DO NOTHING",
    )
    .bind(&user_id)
    .bind(&username)
    .bind(password_hash(&payload.password))
    .bind(&payload.role)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(ApiError::conflict("Username already exists"));
    }
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, 'user_created', $2, $3, now())")
        .bind(&actor.username)
        .bind(&username)
        .bind(format!("role={}", payload.role))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let user = fetch_user_by_id(&state, &user_id).await?;
    Ok((StatusCode::CREATED, Json(UserView::from(&user))))
}

#[derive(Deserialize)]
struct EditUserPayload {
    role: String,
    active: bool,
    password: Option<String>,
}

async fn edit_user(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(user_id): Path<String>,
    Json(payload): Json<EditUserPayload>,
) -> Result<Json<UserView>, ApiError> {
    let actor = require_real_admin(&admin)?;
    if !valid_role(&payload.role) {
        return Err(ApiError::bad_request("Invalid role"));
    }
    if let Some(password) = &payload.password {
        if password.len() < 12 || password.len() > 128 {
            return Err(ApiError::bad_request("Password must be at least 12 characters"));
        }
    }

    let mut tx = state.db.begin().await?;
    sqlx::query("SELECT id FROM auth_control WHERE id = 1 FOR UPDATE")
        .fetch_optional(&mut *tx)
        .await?;
    let (actor_active, actor_role): (bool, String) =
        sqlx::query_as("SELECT active, role FROM users WHERE id = $1")
            .bind(&actor.id)
            .fetch_one(&mut *tx)
            .await?;
    if !actor_active || actor_role != "admin" {
        return Err(ApiError::forbidden("Admin access required"));
    }

    let target = sqlx::query("SELECT id, role, active, username FROM users WHERE id = $1 FOR UPDATE")
        .bind(&user_id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(target) = target else {
        return Err(ApiError::not_found("User not found"));
    };
    let target_role: String = target.get("role");
    let target_active: bool = target.get("active");
    let target_username: String = target.get("username");

    if target_role == "admin" && target_active && (payload.role != "admin" || !payload.active) {
        let admin_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM users WHERE active = true AND role = 'admin'",
        )
        .fetch_one(&mut *tx)
        .await?;
        if admin_count <= 1 {
            return Err(ApiError::conflict("Keep at least one active administrator"));
        }
    }
    if payload.password.is_some() && user_id == actor.id {
        return Err(ApiError::bad_request("Use Change password to change your own password"));
    }

    if let Some(password) = &payload.password {
        sqlx::query(
            "UPDATE users SET role = $1, active = $2, password_hash = $3, must_change_password = true WHERE id = $4",
        )
        .bind(&payload.role)
        .bind(payload.active)
        .bind(password_hash(password))
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query("UPDATE users SET role = $1, active = $2 WHERE id = $3")
            .bind(&payload.role)
            .bind(payload.active)
            .bind(&user_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM user_sessions WHERE user_id = $1")
        .bind(&user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, 'user_updated', $2, $3, now())")
        .bind(&actor.username)
        .bind(&target_username)
        .bind(format!(
            "role={}; active={}; password_reset={}",
            payload.role,
            payload.active,
            payload.password.is_some()
        ))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let user = fetch_user_by_id(&state, &user_id).await?;
    Ok(Json(UserView::from(&user)))
}

#[derive(Serialize, sqlx::FromRow)]
struct AuditEntry {
    actor: String,
    action: String,
    target: String,
    details: String,
    created_at: DateTime<Utc>,
}

async fn audit_history(
    State(state): State<Arc<AppState>>,
    admin: Admin,
) -> Result<Json<Vec<AuditEntry>>, ApiError> {
    require_real_admin(&admin)?;
    let rows = sqlx::query_as::<_, AuditEntry>(
        "SELECT actor, action, target, details, created_at FROM account_audit ORDER BY id DESC LIMIT 100",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}
