//! A saved, reusable script library. Running one against a device queues
//! the exact same RUN_COMMAND job the ad-hoc "Run command" feature uses
//! (see deployment.rs::run_command) -- this module just gives admins a
//! named, reusable body instead of retyping the same command every time,
//! and a bulk-run path that queues it across several devices at once.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::Admin;
use crate::error::ApiError;
use crate::models::Device;
use crate::AppState;

const MAX_SCRIPT_BODY: usize = 4096;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/scripts", get(list_scripts).post(create_script))
        .route("/api/v1/admin/scripts/:id", put(update_script).delete(delete_script))
        .route("/api/v1/admin/devices/:id/scripts/:script_id/run", post(run_script))
}

#[derive(Deserialize)]
struct ScriptPayload {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default = "default_platform")]
    platform: String,
    body: String,
}

fn default_platform() -> String {
    "any".to_string()
}

fn validate_script(payload: &ScriptPayload) -> Result<(), ApiError> {
    if payload.name.trim().is_empty() || payload.name.len() > 255 {
        return Err(ApiError::bad_request("A script name is required"));
    }
    if payload.description.len() > 500 {
        return Err(ApiError::bad_request("Description must be 500 characters or fewer"));
    }
    if !matches!(payload.platform.as_str(), "any" | "linux" | "windows" | "freebsd") {
        return Err(ApiError::bad_request("platform must be any, linux, windows, or freebsd"));
    }
    if payload.body.trim().is_empty() || payload.body.len() > MAX_SCRIPT_BODY {
        return Err(ApiError::bad_request(format!("Script body must be 1-{MAX_SCRIPT_BODY} characters")));
    }
    Ok(())
}

fn script_view(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "description": row.get::<String, _>("description"),
        "platform": row.get::<String, _>("platform"),
        "body": row.get::<String, _>("body"),
        "created_at": row.get::<chrono::DateTime<Utc>, _>("created_at"),
    })
}

async fn list_scripts(State(state): State<Arc<AppState>>, _admin: Admin) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = sqlx::query("SELECT id, name, description, platform, body, created_at FROM scripts ORDER BY name ASC")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows.iter().map(script_view).collect()))
}

async fn create_script(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Json(payload): Json<ScriptPayload>,
) -> Result<impl IntoResponse, ApiError> {
    validate_script(&payload)?;
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO scripts (id, name, description, platform, body) VALUES ($1, $2, $3, $4, $5)")
        .bind(&id)
        .bind(payload.name.trim())
        .bind(&payload.description)
        .bind(&payload.platform)
        .bind(&payload.body)
        .execute(&state.db)
        .await?;
    let row = sqlx::query("SELECT id, name, description, platform, body, created_at FROM scripts WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok((StatusCode::CREATED, Json(script_view(&row))))
}

async fn update_script(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
    Json(payload): Json<ScriptPayload>,
) -> Result<Json<Value>, ApiError> {
    validate_script(&payload)?;
    let result = sqlx::query("UPDATE scripts SET name=$1, description=$2, platform=$3, body=$4 WHERE id=$5")
        .bind(payload.name.trim())
        .bind(&payload.description)
        .bind(&payload.platform)
        .bind(&payload.body)
        .bind(&id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Script not found"));
    }
    let row = sqlx::query("SELECT id, name, description, platform, body, created_at FROM scripts WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(script_view(&row)))
}

async fn delete_script(State(state): State<Arc<AppState>>, _admin: Admin, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM scripts WHERE id = $1").bind(&id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

// Mirrors deployment.rs's own private version-gate check -- each module
// that gates a job type on agent version keeps its own copy rather than
// sharing one, matching how this codebase already does it elsewhere.
fn supports_run_command(device: &Device) -> bool {
    let Some(version) = device.agent_version.as_deref() else { return false };
    let mut parts = version.split('.').take(2).map(|p| p.parse::<i32>());
    let (Some(Ok(major)), Some(Ok(minor))) = (parts.next(), parts.next()) else { return false };
    (major, minor) >= (0, 16)
}

async fn run_script(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path((device_id, script_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let device = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1",
    )
    .bind(&device_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(device) = device else {
        return Err(ApiError::not_found("Device not found"));
    };
    if !supports_run_command(&device) {
        return Err(ApiError::conflict("Upgrade this device's existing agent to 0.16.0 and run a patch scan first"));
    }
    let script_row = sqlx::query("SELECT name, platform, body FROM scripts WHERE id = $1")
        .bind(&script_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(script_row) = script_row else {
        return Err(ApiError::not_found("Script not found"));
    };
    let script_name: String = script_row.get("name");
    let script_platform: String = script_row.get("platform");
    let body: String = script_row.get("body");
    if script_platform != "any" && script_platform != device.platform {
        return Err(ApiError::bad_request(format!(
            "This script is marked for {script_platform}, not {}",
            device.platform
        )));
    }

    let job_id = Uuid::new_v4().to_string();
    let mut tx = state.db.begin().await?;
    crate::models::insert_job(&mut *tx, &job_id, &device_id, "RUN_COMMAND", json!({ "command": body, "confirmed": true })).await?;
    let actor = admin.0.user().map(|u| u.username.as_str()).unwrap_or("bootstrap");
    let details: String = format!("script: {script_name}").chars().take(255).collect();
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, 'run_command', $2, $3, now())")
        .bind(actor)
        .bind(&device.hostname)
        .bind(details)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": job_id, "device_id": device_id, "script": script_name }))))
}
