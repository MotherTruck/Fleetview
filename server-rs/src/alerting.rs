//! Alerting: outbound notification channels (webhooks) + the rules that
//! decide when to use them. Two triggering mechanisms:
//!
//!   - Level-triggered conditions (device_offline, resource_threshold,
//!     vulnerability_found) are evaluated on a timer by evaluate_loop,
//!     which notifies once when a (rule, device) pair starts matching and
//!     once when it stops (tracked via alert_firings), rather than every
//!     tick while the condition persists.
//!   - job_failed is a one-time event, fired directly from
//!     devices::complete_job the moment a job's status becomes "failed"
//!     (see notify_job_failed) -- there's no "still failed" state to
//!     track or resolve.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::auth::Admin;
use crate::error::ApiError;
use crate::models::Device;
use crate::AppState;

const EVALUATE_INTERVAL_SECONDS: u64 = 60;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/admin/notification-channels",
            get(list_channels).post(create_channel),
        )
        .route("/api/v1/admin/notification-channels/:id", put(update_channel).delete(delete_channel))
        .route("/api/v1/admin/notification-channels/:id/test", post(test_channel))
        .route("/api/v1/admin/alert-rules", get(list_rules).post(create_rule))
        .route("/api/v1/admin/alert-rules/:id", put(update_rule).delete(delete_rule))
}

// -- notification channels --

#[derive(Deserialize)]
struct ChannelPayload {
    name: String,
    url: String,
    #[serde(default = "default_format")]
    format: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_format() -> String {
    "generic".to_string()
}
fn default_true() -> bool {
    true
}

fn validate_channel(name: &str, url: &str, format: &str) -> Result<(), ApiError> {
    if name.trim().is_empty() || name.len() > 255 {
        return Err(ApiError::bad_request("A channel name is required"));
    }
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ApiError::bad_request("Webhook URL must be http(s)"));
    }
    if !matches!(format, "generic" | "slack") {
        return Err(ApiError::bad_request("format must be \"generic\" or \"slack\""));
    }
    Ok(())
}

async fn list_channels(State(state): State<Arc<AppState>>, _admin: Admin) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = sqlx::query("SELECT id, name, url, format, enabled, created_at FROM notification_channels ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await?;
    Ok(Json(rows.iter().map(channel_view).collect()))
}

fn channel_view(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "url": row.get::<String, _>("url"),
        "format": row.get::<String, _>("format"),
        "enabled": row.get::<bool, _>("enabled"),
        "created_at": row.get::<chrono::DateTime<Utc>, _>("created_at"),
    })
}

async fn create_channel(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Json(payload): Json<ChannelPayload>,
) -> Result<impl IntoResponse, ApiError> {
    validate_channel(&payload.name, &payload.url, &payload.format)?;
    let id = Uuid::new_v4().to_string();
    sqlx::query("INSERT INTO notification_channels (id, name, url, format, enabled) VALUES ($1, $2, $3, $4, $5)")
        .bind(&id)
        .bind(payload.name.trim())
        .bind(&payload.url)
        .bind(&payload.format)
        .bind(payload.enabled)
        .execute(&state.db)
        .await?;
    let row = sqlx::query("SELECT id, name, url, format, enabled, created_at FROM notification_channels WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok((StatusCode::CREATED, Json(channel_view(&row))))
}

async fn update_channel(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
    Json(payload): Json<ChannelPayload>,
) -> Result<Json<Value>, ApiError> {
    validate_channel(&payload.name, &payload.url, &payload.format)?;
    let result = sqlx::query("UPDATE notification_channels SET name=$1, url=$2, format=$3, enabled=$4 WHERE id=$5")
        .bind(payload.name.trim())
        .bind(&payload.url)
        .bind(&payload.format)
        .bind(payload.enabled)
        .bind(&id)
        .execute(&state.db)
        .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Notification channel not found"));
    }
    let row = sqlx::query("SELECT id, name, url, format, enabled, created_at FROM notification_channels WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(channel_view(&row)))
}

async fn delete_channel(State(state): State<Arc<AppState>>, _admin: Admin, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM notification_channels WHERE id = $1").bind(&id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn test_channel(State(state): State<Arc<AppState>>, _admin: Admin, Path(id): Path<String>) -> Result<Json<Value>, ApiError> {
    let row = sqlx::query("SELECT url, format FROM notification_channels WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;
    let Some(row) = row else { return Err(ApiError::not_found("Notification channel not found")) };
    let url: String = row.get("url");
    let format: String = row.get("format");
    match send_notification(&url, &format, "FleetView test notification", "This is a test notification from FleetView's Admin \u{2192} Alerting page.").await {
        Ok(()) => Ok(Json(json!({ "status": "sent" }))),
        Err(error) => Err(ApiError::new(StatusCode::BAD_GATEWAY, format!("Could not deliver test notification: {error}"))),
    }
}

async fn send_notification(url: &str, format: &str, title: &str, message: &str) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|error| error.to_string())?;
    let body = if format == "slack" {
        json!({ "text": format!("*{title}*\n{message}") })
    } else {
        json!({ "title": title, "message": message, "source": "fleetview" })
    };
    let response = client.post(url).json(&body).send().await.map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    Ok(())
}

async fn notify_all_channels(db: &PgPool, title: &str, message: &str) {
    let channels = sqlx::query("SELECT url, format FROM notification_channels WHERE enabled = true")
        .fetch_all(db)
        .await;
    let Ok(channels) = channels else { return };
    for row in channels {
        let url: String = row.get("url");
        let format: String = row.get("format");
        if let Err(error) = send_notification(&url, &format, title, message).await {
            tracing::warn!("notification delivery to {url} failed: {error}");
        }
    }
}

// -- alert rules --

#[derive(Deserialize)]
struct RulePayload {
    name: String,
    kind: String,
    #[serde(default)]
    metric: Option<String>,
    #[serde(default)]
    threshold_value: Option<f64>,
    #[serde(default)]
    tag_filter: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

const VALID_KINDS: &[&str] = &["device_offline", "resource_threshold", "vulnerability_found", "job_failed"];

fn validate_rule(payload: &RulePayload) -> Result<(), ApiError> {
    if payload.name.trim().is_empty() || payload.name.len() > 255 {
        return Err(ApiError::bad_request("A rule name is required"));
    }
    if !VALID_KINDS.contains(&payload.kind.as_str()) {
        return Err(ApiError::bad_request(format!("kind must be one of: {}", VALID_KINDS.join(", "))));
    }
    if payload.kind == "resource_threshold" {
        if !matches!(payload.metric.as_deref(), Some("cpu") | Some("memory") | Some("disk")) {
            return Err(ApiError::bad_request("resource_threshold rules need metric = cpu, memory, or disk"));
        }
        let Some(value) = payload.threshold_value else {
            return Err(ApiError::bad_request("resource_threshold rules need a threshold_value (percent)"));
        };
        if !(1.0..=100.0).contains(&value) {
            return Err(ApiError::bad_request("threshold_value must be between 1 and 100"));
        }
    }
    if payload.kind == "device_offline" {
        let Some(value) = payload.threshold_value else {
            return Err(ApiError::bad_request("device_offline rules need a threshold_value (minutes)"));
        };
        if !(1.0..=10080.0).contains(&value) {
            return Err(ApiError::bad_request("threshold_value must be between 1 minute and 7 days"));
        }
    }
    Ok(())
}

async fn list_rules(State(state): State<Arc<AppState>>, _admin: Admin) -> Result<Json<Vec<Value>>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, name, kind, metric, threshold_value, tag_filter, enabled, created_at FROM alert_rules ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.iter().map(rule_view).collect()))
}

fn rule_view(row: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": row.get::<String, _>("id"),
        "name": row.get::<String, _>("name"),
        "kind": row.get::<String, _>("kind"),
        "metric": row.get::<Option<String>, _>("metric"),
        "threshold_value": row.get::<Option<f64>, _>("threshold_value"),
        "tag_filter": row.get::<Option<String>, _>("tag_filter"),
        "enabled": row.get::<bool, _>("enabled"),
        "created_at": row.get::<chrono::DateTime<Utc>, _>("created_at"),
    })
}

async fn create_rule(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Json(payload): Json<RulePayload>,
) -> Result<impl IntoResponse, ApiError> {
    validate_rule(&payload)?;
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO alert_rules (id, name, kind, metric, threshold_value, tag_filter, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(&id)
    .bind(payload.name.trim())
    .bind(&payload.kind)
    .bind(&payload.metric)
    .bind(payload.threshold_value)
    .bind(payload.tag_filter.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(payload.enabled)
    .execute(&state.db)
    .await?;
    let row = sqlx::query("SELECT id, name, kind, metric, threshold_value, tag_filter, enabled, created_at FROM alert_rules WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok((StatusCode::CREATED, Json(rule_view(&row))))
}

async fn update_rule(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
    Json(payload): Json<RulePayload>,
) -> Result<Json<Value>, ApiError> {
    validate_rule(&payload)?;
    let result = sqlx::query(
        "UPDATE alert_rules SET name=$1, kind=$2, metric=$3, threshold_value=$4, tag_filter=$5, enabled=$6 WHERE id=$7",
    )
    .bind(payload.name.trim())
    .bind(&payload.kind)
    .bind(&payload.metric)
    .bind(payload.threshold_value)
    .bind(payload.tag_filter.as_deref().map(str::trim).filter(|s| !s.is_empty()))
    .bind(payload.enabled)
    .bind(&id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Alert rule not found"));
    }
    let row = sqlx::query("SELECT id, name, kind, metric, threshold_value, tag_filter, enabled, created_at FROM alert_rules WHERE id = $1")
        .bind(&id)
        .fetch_one(&state.db)
        .await?;
    Ok(Json(rule_view(&row)))
}

async fn delete_rule(State(state): State<Arc<AppState>>, _admin: Admin, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    sqlx::query("DELETE FROM alert_rules WHERE id = $1").bind(&id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

// -- event-driven: job failures --

/// Called from devices::complete_job right after a job's status is
/// written as "failed". Fire-and-forget (the caller tokio::spawns this)
/// so a slow or unreachable webhook never adds latency to the agent's
/// job-completion request.
pub async fn notify_job_failed(db: &PgPool, device: &Device, job_type: &str, job_id: &str, error: Option<&str>) {
    let has_rule = matching_enabled_rule_exists(db, "job_failed", device).await;
    if !has_rule {
        return;
    }
    let name = device_label(device);
    let title = format!("Job failed on {name}");
    let message = format!(
        "{job_type} (job {job_id}) failed on {name}.{}",
        error.map(|e| format!(" Error: {e}")).unwrap_or_default()
    );
    notify_all_channels(db, &title, &message).await;
}

async fn matching_enabled_rule_exists(db: &PgPool, kind: &str, device: &Device) -> bool {
    let rules = sqlx::query("SELECT tag_filter FROM alert_rules WHERE kind = $1 AND enabled = true")
        .bind(kind)
        .fetch_all(db)
        .await;
    let Ok(rules) = rules else { return false };
    rules.iter().any(|row| {
        let tag_filter: Option<String> = row.get("tag_filter");
        rule_matches_device_tag(tag_filter.as_deref(), device)
    })
}

fn rule_matches_device_tag(tag_filter: Option<&str>, device: &Device) -> bool {
    let Some(tag) = tag_filter else { return true };
    device
        .inventory
        .get("_tags")
        .and_then(Value::as_array)
        .map(|tags| tags.iter().any(|t| t.as_str() == Some(tag)))
        .unwrap_or(false)
}

fn device_label(device: &Device) -> String {
    device.display_name.clone().unwrap_or_else(|| device.hostname.clone())
}

// -- level-triggered evaluation loop --

pub async fn evaluate_loop(db: PgPool) {
    loop {
        if let Err(error) = evaluate_once(&db).await {
            tracing::error!("alert evaluation loop iteration failed: {error}");
        }
        tokio::time::sleep(Duration::from_secs(EVALUATE_INTERVAL_SECONDS)).await;
    }
}

async fn evaluate_once(db: &PgPool) -> Result<(), sqlx::Error> {
    let rules = sqlx::query(
        "SELECT id, name, kind, metric, threshold_value, tag_filter FROM alert_rules \
         WHERE enabled = true AND kind != 'job_failed'",
    )
    .fetch_all(db)
    .await?;
    if rules.is_empty() {
        return Ok(());
    }
    let devices = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices",
    )
    .fetch_all(db)
    .await?;

    for rule_row in &rules {
        let rule_id: String = rule_row.get("id");
        let rule_name: String = rule_row.get("name");
        let kind: String = rule_row.get("kind");
        let metric: Option<String> = rule_row.get("metric");
        let threshold: Option<f64> = rule_row.get("threshold_value");
        let tag_filter: Option<String> = rule_row.get("tag_filter");

        for device in &devices {
            if !rule_matches_device_tag(tag_filter.as_deref(), device) {
                continue;
            }
            let (firing, detail) = evaluate_condition(&kind, metric.as_deref(), threshold, device);
            let already_firing = sqlx::query_scalar::<_, i32>(
                "SELECT id FROM alert_firings WHERE rule_id = $1 AND device_id = $2",
            )
            .bind(&rule_id)
            .bind(&device.id)
            .fetch_optional(db)
            .await?
            .is_some();

            if firing && !already_firing {
                sqlx::query("INSERT INTO alert_firings (rule_id, device_id) VALUES ($1, $2) ON CONFLICT DO NOTHING")
                    .bind(&rule_id)
                    .bind(&device.id)
                    .execute(db)
                    .await?;
                let name = device_label(device);
                notify_all_channels(
                    db,
                    &format!("Alert: {rule_name} -- {name}"),
                    &detail.unwrap_or_else(|| format!("{rule_name} is firing for {name}.")),
                )
                .await;
            } else if !firing && already_firing {
                sqlx::query("DELETE FROM alert_firings WHERE rule_id = $1 AND device_id = $2")
                    .bind(&rule_id)
                    .bind(&device.id)
                    .execute(db)
                    .await?;
                let name = device_label(device);
                notify_all_channels(
                    db,
                    &format!("Resolved: {rule_name} -- {name}"),
                    &format!("{rule_name} is no longer firing for {name}."),
                )
                .await;
            }
        }
    }
    Ok(())
}

/// Returns (is_firing, optional human-readable detail for the notification).
fn evaluate_condition(kind: &str, metric: Option<&str>, threshold: Option<f64>, device: &Device) -> (bool, Option<String>) {
    match kind {
        "device_offline" => {
            let Some(minutes) = threshold else { return (false, None) };
            let offline_since = Utc::now() - device.last_seen;
            let firing = offline_since.num_seconds() as f64 > minutes * 60.0;
            (firing, Some(format!("{} has not checked in for over {} minutes (last seen {}).", device_label(device), minutes as i64, device.last_seen.to_rfc3339())))
        }
        "resource_threshold" => {
            let Some(threshold) = threshold else { return (false, None) };
            let current = device.inventory.get("_monitoring").and_then(|m| m.get("current"));
            let Some(current) = current else { return (false, None) };
            let percent = match metric {
                Some("cpu") => current.get("cpu_percent").and_then(Value::as_f64),
                Some("memory") => {
                    let used = current.get("memory_used_bytes").and_then(Value::as_f64);
                    let total = current.get("memory_total_bytes").and_then(Value::as_f64);
                    match (used, total) {
                        (Some(u), Some(t)) if t > 0.0 => Some(u / t * 100.0),
                        _ => None,
                    }
                }
                Some("disk") => {
                    let used = current.get("disk_used_bytes").and_then(Value::as_f64);
                    let total = current.get("disk_total_bytes").and_then(Value::as_f64);
                    match (used, total) {
                        (Some(u), Some(t)) if t > 0.0 => Some(u / t * 100.0),
                        _ => None,
                    }
                }
                _ => None,
            };
            let Some(percent) = percent else { return (false, None) };
            let firing = percent > threshold;
            (firing, Some(format!("{} {} usage is {:.1}% (threshold {:.0}%).", device_label(device), metric.unwrap_or("resource"), percent, threshold)))
        }
        "vulnerability_found" => {
            let vulnerabilities = device
                .inventory
                .get("_security")
                .and_then(|s| s.get("vulnerabilities"))
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let critical_or_high = vulnerabilities.iter().any(|v| {
                matches!(
                    v.get("severity").and_then(Value::as_str).map(str::to_uppercase).as_deref(),
                    Some("CRITICAL") | Some("HIGH")
                )
            });
            (critical_or_high, Some(format!("{} has a CRITICAL or HIGH severity vulnerability finding.", device_label(device))))
        }
        _ => (false, None),
    }
}
