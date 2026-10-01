//! Mirrors the remaining pieces of server/app/main.py: compliance history
//! (Reports tab trend charts) and the software package catalog (Deploy
//! tab). Everything else in that file (device/agent/job core, fleet
//! settings, vulnerability schedule) landed in devices.rs already.
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use chrono::{NaiveDate, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{Operator, Viewer};
use crate::error::ApiError;
use crate::models::Package;
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/reports/history", get(compliance_history))
        .route("/api/v1/admin/packages", get(list_packages).post(create_package))
        .route(
            "/api/v1/admin/packages/:id",
            axum::routing::put(update_package).delete(delete_package),
        )
}

#[derive(Deserialize)]
struct HistoryQuery {
    #[serde(default = "default_days")]
    days: i64,
    device_id: Option<String>,
    start: Option<NaiveDate>,
    end: Option<NaiveDate>,
}

fn default_days() -> i64 {
    30
}

#[derive(Serialize)]
struct HistoryDay {
    date: String,
    device_count: i64,
    fully_patched_percent: f64,
    no_critical_high_percent: f64,
    online_percent: f64,
    total_updates_needed: i64,
    total_vulnerabilities: i64,
}

fn round1(value: f64) -> f64 {
    (value * 10.0).round() / 10.0
}

async fn compliance_history(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Query(query): Query<HistoryQuery>,
) -> Result<Json<Vec<HistoryDay>>, ApiError> {
    if !(1..=3660).contains(&query.days) {
        return Err(ApiError::bad_request("days must be between 1 and 3660"));
    }
    if query.start.is_some() != query.end.is_some() {
        return Err(ApiError::bad_request("Provide both start and end dates"));
    }
    let end_date = query.end.unwrap_or_else(|| Utc::now().date_naive());
    let start_date = query.start.unwrap_or_else(|| end_date - chrono::Duration::days(query.days - 1));
    if start_date > end_date || (end_date - start_date).num_days() >= 3660 {
        return Err(ApiError::bad_request("Date range must be ordered and at most 3660 days"));
    }
    if let Some(device_id) = &query.device_id {
        let exists: Option<String> = sqlx::query_scalar("SELECT id FROM devices WHERE id = $1")
            .bind(device_id)
            .fetch_optional(&state.db)
            .await?;
        if exists.is_none() {
            return Err(ApiError::not_found("Device not found"));
        }
    }

    let start_str = start_date.format("%Y-%m-%d").to_string();
    let end_str = end_date.format("%Y-%m-%d").to_string();
    let rows = if let Some(device_id) = &query.device_id {
        sqlx::query(
            "SELECT snapshot_date, update_count, critical_vulnerability_count, high_vulnerability_count, \
             vulnerability_count, online FROM compliance_snapshots \
             WHERE snapshot_date >= $1 AND snapshot_date <= $2 AND device_id = $3 ORDER BY snapshot_date",
        )
        .bind(&start_str)
        .bind(&end_str)
        .bind(device_id)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query(
            "SELECT snapshot_date, update_count, critical_vulnerability_count, high_vulnerability_count, \
             vulnerability_count, online FROM compliance_snapshots \
             WHERE snapshot_date >= $1 AND snapshot_date <= $2 ORDER BY snapshot_date",
        )
        .bind(&start_str)
        .bind(&end_str)
        .fetch_all(&state.db)
        .await?
    };

    let mut by_date: std::collections::BTreeMap<String, Vec<_>> = std::collections::BTreeMap::new();
    for row in rows {
        let date: String = row.get("snapshot_date");
        by_date.entry(date).or_default().push(row);
    }

    let mut history = Vec::new();
    for (date, day) in by_date {
        let count = day.len() as i64;
        let fully_patched = day.iter().filter(|r| r.get::<i32, _>("update_count") == 0).count() as f64;
        let no_crit_high = day
            .iter()
            .filter(|r| r.get::<i32, _>("critical_vulnerability_count") == 0 && r.get::<i32, _>("high_vulnerability_count") == 0)
            .count() as f64;
        let online = day.iter().filter(|r| r.get::<bool, _>("online")).count() as f64;
        let total_updates: i64 = day.iter().map(|r| r.get::<i32, _>("update_count") as i64).sum();
        let total_vulns: i64 = day.iter().map(|r| r.get::<i32, _>("vulnerability_count") as i64).sum();
        history.push(HistoryDay {
            date,
            device_count: count,
            fully_patched_percent: round1(fully_patched / count as f64 * 100.0),
            no_critical_high_percent: round1(no_crit_high / count as f64 * 100.0),
            online_percent: round1(online / count as f64 * 100.0),
            total_updates_needed: total_updates,
            total_vulnerabilities: total_vulns,
        });
    }
    Ok(Json(history))
}

// -- package catalog --

async fn list_packages(State(state): State<Arc<AppState>>, _viewer: Viewer) -> Result<Json<Vec<Package>>, ApiError> {
    let packages = sqlx::query_as::<_, Package>(
        "SELECT id, name, description, version, category, pacman_name, apt_name, winget_id, created_at, updated_at \
         FROM packages ORDER BY name ASC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(packages))
}

#[derive(Deserialize)]
struct PackageUpsertPayload {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    pacman_name: String,
    #[serde(default)]
    apt_name: String,
    #[serde(default)]
    winget_id: String,
}

impl PackageUpsertPayload {
    fn validate(&self) -> Result<(), ApiError> {
        if self.name.is_empty() || self.name.len() > 255 {
            return Err(ApiError::bad_request("Invalid package name"));
        }
        if self.pacman_name.trim().is_empty() && self.apt_name.trim().is_empty() && self.winget_id.trim().is_empty() {
            return Err(ApiError::bad_request("Set at least one platform's package name or ID"));
        }
        Ok(())
    }
}

async fn create_package(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Json(payload): Json<PackageUpsertPayload>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    payload.validate()?;
    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO packages (id, name, description, version, category, pacman_name, apt_name, winget_id, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now())",
    )
    .bind(&id)
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.version)
    .bind(&payload.category)
    .bind(&payload.pacman_name)
    .bind(&payload.apt_name)
    .bind(&payload.winget_id)
    .execute(&state.db)
    .await?;
    let package = sqlx::query_as::<_, Package>(
        "SELECT id, name, description, version, category, pacman_name, apt_name, winget_id, created_at, updated_at \
         FROM packages WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;
    Ok((StatusCode::CREATED, Json(package)))
}

async fn update_package(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<PackageUpsertPayload>,
) -> Result<Json<Package>, ApiError> {
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM packages WHERE id = $1")
        .bind(&id)
        .fetch_optional(&state.db)
        .await?;
    if exists.is_none() {
        return Err(ApiError::not_found("Package not found"));
    }
    payload.validate()?;
    sqlx::query(
        "UPDATE packages SET name=$1, description=$2, version=$3, category=$4, pacman_name=$5, apt_name=$6, \
         winget_id=$7, updated_at=$8 WHERE id=$9",
    )
    .bind(&payload.name)
    .bind(&payload.description)
    .bind(&payload.version)
    .bind(&payload.category)
    .bind(&payload.pacman_name)
    .bind(&payload.apt_name)
    .bind(&payload.winget_id)
    .bind(Utc::now())
    .bind(&id)
    .execute(&state.db)
    .await?;
    let package = sqlx::query_as::<_, Package>(
        "SELECT id, name, description, version, category, pacman_name, apt_name, winget_id, created_at, updated_at \
         FROM packages WHERE id = $1",
    )
    .bind(&id)
    .fetch_one(&state.db)
    .await?;
    Ok(Json(package))
}

async fn delete_package(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let result = sqlx::query("DELETE FROM packages WHERE id = $1").bind(&id).execute(&state.db).await?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Package not found"));
    }
    Ok(StatusCode::NO_CONTENT)
}
