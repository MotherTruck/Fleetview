//! Mirrors server/app/enrollment.py (the pure token_status helper) plus
//! the enrollment-token admin endpoints and the agent-facing /enroll
//! endpoint from main.py -- device CRUD/report endpoints land in the next
//! increment, but enroll necessarily creates a Device row, so it's here.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Admin;
use crate::error::ApiError;
use crate::security::{new_agent_token, new_enrollment_token, secure_equal, token_hash};
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/agent/enroll", post(enroll))
        .route(
            "/api/v1/admin/enrollment-tokens",
            get(list_enrollment_tokens).post(create_enrollment_token),
        )
        .route(
            "/api/v1/admin/enrollment-tokens/:id",
            delete(revoke_enrollment_token),
        )
}

/// Classifies a token as used, revoked, expired, or active, in that
/// precedence -- matches server/app/enrollment.py's token_status exactly.
pub fn token_status(
    used_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> &'static str {
    if used_at.is_some() {
        "used"
    } else if revoked_at.is_some() {
        "revoked"
    } else if expires_at <= now {
        "expired"
    } else {
        "active"
    }
}

#[derive(Deserialize)]
struct EnrollRequest {
    enrollment_token: String,
    hostname: String,
    #[serde(default = "default_platform")]
    platform: String,
    agent_version: String,
}

fn default_platform() -> String {
    "linux".to_string()
}

#[cfg(test)]
mod token_status_tests {
    //! Ports server/tests/test_enrollment_tokens.py's TokenStatusTests.
    //! The Python suite also checks that naive (timezone-less) datetimes are
    //! treated as UTC -- that bug class is structurally impossible here,
    //! since chrono::DateTime<Utc> is always timezone-aware, so there's no
    //! equivalent case to port.
    use super::*;

    fn now() -> DateTime<Utc> {
        "2026-01-01T12:00:00Z".parse().unwrap()
    }

    #[test]
    fn active() {
        assert_eq!(token_status(None, None, now() + Duration::hours(1), now()), "active");
    }

    #[test]
    fn expired_at_and_after_the_deadline() {
        assert_eq!(token_status(None, None, now(), now()), "expired");
        assert_eq!(token_status(None, None, now() - Duration::seconds(1), now()), "expired");
    }

    #[test]
    fn revoked() {
        assert_eq!(token_status(None, Some(now()), now() + Duration::hours(1), now()), "revoked");
    }

    #[test]
    fn used_wins_over_everything() {
        assert_eq!(token_status(Some(now()), Some(now()), now() - Duration::days(1), now()), "used");
    }

    #[test]
    fn revoked_wins_over_expired() {
        assert_eq!(token_status(None, Some(now()), now() - Duration::days(1), now()), "revoked");
    }
}

async fn enroll(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<EnrollRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.enrollment_token.len() < 16 || payload.hostname.is_empty() || payload.hostname.len() > 255 {
        return Err(ApiError::bad_request("Invalid enrollment request"));
    }
    let now = Utc::now();
    let hashed = token_hash(&payload.enrollment_token);

    let mut tx = state.db.begin().await?;
    // Single-use per-device tokens: one conditional UPDATE, so two agents
    // racing with the same token can't both succeed -- the loser matches
    // zero rows.
    let claimed_result = sqlx::query(
        "UPDATE enrollment_tokens SET used_at = $1 \
         WHERE token_hash = $2 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $1",
    )
    .bind(now)
    .bind(&hashed)
    .execute(&mut *tx)
    .await?;
    let claimed = claimed_result.rows_affected() == 1;

    if !claimed {
        let shared = std::env::var("ENROLLMENT_TOKEN").unwrap_or_default();
        if shared.is_empty() || !secure_equal(&payload.enrollment_token, &shared) {
            return Err(ApiError::unauthorized(
                "Invalid, expired, or already-used enrollment token",
            ));
        }
    }

    let agent_token = new_agent_token();
    let device_id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO devices (id, hostname, platform, agent_version, agent_token_hash, \
         enrolled_at, last_seen, inventory, installed_packages, available_updates) \
         VALUES ($1, $2, $3, $4, $5, now(), now(), '{}', '[]', '[]')",
    )
    .bind(&device_id)
    .bind(&payload.hostname)
    .bind(&payload.platform)
    .bind(&payload.agent_version)
    .bind(token_hash(&agent_token))
    .execute(&mut *tx)
    .await?;
    if claimed {
        sqlx::query("UPDATE enrollment_tokens SET used_by_device_id = $1 WHERE token_hash = $2")
            .bind(&device_id)
            .bind(&hashed)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "device_id": device_id, "agent_token": agent_token })),
    ))
}

#[derive(Serialize)]
struct EnrollmentTokenView {
    id: String,
    label: Option<String>,
    status: &'static str,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    used_at: Option<DateTime<Utc>>,
    device_id: Option<String>,
}

#[derive(Deserialize)]
struct EnrollmentTokenCreate {
    label: Option<String>,
    #[serde(default = "default_ttl_minutes")]
    ttl_minutes: i64,
}

fn default_ttl_minutes() -> i64 {
    60
}

async fn create_enrollment_token(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Json(payload): Json<EnrollmentTokenCreate>,
) -> Result<impl IntoResponse, ApiError> {
    if !(1..=10080).contains(&payload.ttl_minutes) {
        return Err(ApiError::bad_request("ttl_minutes must be between 1 and 10080"));
    }
    let token = new_enrollment_token();
    let now = Utc::now();
    let expires_at = now + Duration::minutes(payload.ttl_minutes);
    let label = payload.label.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO enrollment_tokens (id, token_hash, label, created_at, expires_at) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(&id)
    .bind(token_hash(&token))
    .bind(label)
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;

    let view = EnrollmentTokenView {
        id,
        label: label.map(str::to_string),
        status: token_status(None, None, expires_at, now),
        created_at: now,
        expires_at,
        used_at: None,
        device_id: None,
    };
    let mut body = serde_json::to_value(view).unwrap();
    body["token"] = json!(token);
    Ok((StatusCode::CREATED, Json(body)))
}

async fn list_enrollment_tokens(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> Result<Json<Vec<EnrollmentTokenView>>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, label, created_at, expires_at, used_at, revoked_at, used_by_device_id \
         FROM enrollment_tokens ORDER BY created_at DESC LIMIT 50",
    )
    .fetch_all(&state.db)
    .await?;
    let now = Utc::now();
    let views = rows
        .into_iter()
        .map(|row| {
            let used_at: Option<DateTime<Utc>> = row.get("used_at");
            let revoked_at: Option<DateTime<Utc>> = row.get("revoked_at");
            let expires_at: DateTime<Utc> = row.get("expires_at");
            EnrollmentTokenView {
                id: row.get("id"),
                label: row.get("label"),
                status: token_status(used_at, revoked_at, expires_at, now),
                created_at: row.get("created_at"),
                expires_at,
                used_at,
                device_id: row.get("used_by_device_id"),
            }
        })
        .collect();
    Ok(Json(views))
}

async fn revoke_enrollment_token(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let row = sqlx::query("SELECT used_at, revoked_at FROM enrollment_tokens WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;
    let Some(row) = row else {
        return Err(ApiError::not_found("Enrollment token not found"));
    };
    let used_at: Option<DateTime<Utc>> = row.get("used_at");
    if used_at.is_some() {
        return Err(ApiError::conflict("Token was already used to enroll a device"));
    }
    let revoked_at: Option<DateTime<Utc>> = row.get("revoked_at");
    if revoked_at.is_none() {
        sqlx::query("UPDATE enrollment_tokens SET revoked_at = $1 WHERE id = $2")
            .bind(Utc::now())
            .bind(&id)
            .execute(&state.db)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}
