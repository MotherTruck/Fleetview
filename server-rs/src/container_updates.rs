//! Docker image update policies and the fleet-wide, deduplicated-by-image
//! view they're configured against -- the Watchtower-style piece of the
//! Patching tab. The actual pull/compare/recreate work happens entirely
//! agent-side (agent/internal/containers/update.go); this module decides
//! WHICH containers that applies to and WHEN, then queues the same
//! UPDATE_CONTAINER job devices.rs's create_job already validates for a
//! manually-triggered check/apply.
//!
//! Policies are keyed by image reference (e.g. "nginx:latest"), not by any
//! particular device or container, since the whole point is "one entry
//! even if five machines run the same image" -- the image_name = '*' row
//! (seeded by migration 0009) is the fleet-wide default for any image
//! with no row of its own, so there's exactly one place that default
//! lives rather than a second fleet_settings column to keep in sync with
//! this table.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{Operator, Viewer};
use crate::error::ApiError;
use crate::models::{insert_job, Device};
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/container-updates", get(list_container_updates))
        .route(
            "/api/v1/admin/container-updates/policy/:image_name",
            axum::routing::put(set_policy).delete(delete_policy),
        )
}

#[derive(Debug, Clone)]
struct Policy {
    mode: String,
    excluded_device_ids: Vec<String>,
}

async fn load_policies(pool: &sqlx::PgPool) -> Result<HashMap<String, Policy>, sqlx::Error> {
    let rows = sqlx::query("SELECT image_name, mode, excluded_device_ids FROM container_update_policies")
        .fetch_all(pool)
        .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let image_name: String = row.get("image_name");
            let mode: String = row.get("mode");
            let excluded: Value = row.get("excluded_device_ids");
            let excluded_device_ids = excluded
                .as_array()
                .map(|list| list.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            (image_name, Policy { mode, excluded_device_ids })
        })
        .collect())
}

/// Resolves the policy that actually governs image_name: its own row if
/// one exists, else the '*' fleet-wide default, else a hardcoded "manual"
/// fallback (reachable only if migration 0009's seed row were ever
/// deleted, which nothing in this module does).
fn effective_policy<'a>(policies: &'a HashMap<String, Policy>, image_name: &str) -> (&'a str, &'a [String], bool) {
    if let Some(policy) = policies.get(image_name) {
        return (policy.mode.as_str(), policy.excluded_device_ids.as_slice(), true);
    }
    match policies.get("*") {
        Some(policy) => (policy.mode.as_str(), policy.excluded_device_ids.as_slice(), false),
        None => ("manual", &[], false),
    }
}

async fn list_container_updates(State(state): State<Arc<AppState>>, _viewer: Viewer) -> Result<Json<Value>, ApiError> {
    let devices = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices ORDER BY hostname ASC",
    )
    .fetch_all(&state.db)
    .await?;
    let policies = load_policies(&state.db).await?;

    let mut by_image: std::collections::BTreeMap<String, Vec<Value>> = std::collections::BTreeMap::new();
    for device in &devices {
        let Some(list) = device.inventory.get("docker_containers").and_then(Value::as_array) else { continue };
        for container in list {
            let Some(image) = container.get("image").and_then(Value::as_str) else { continue };
            by_image.entry(image.to_string()).or_default().push(json!({
                "device_id": device.id,
                "hostname": device.display_name.clone().unwrap_or_else(|| device.hostname.clone()),
                "container_id": container.get("id"),
                "container_name": container.get("name"),
                "state": container.get("state"),
                "update_available": container.get("update_available"),
                "update_checked_at": container.get("update_checked_at"),
            }));
        }
    }

    let default_mode = policies.get("*").map(|p| p.mode.clone()).unwrap_or_else(|| "manual".to_string());
    let images: Vec<Value> = by_image
        .into_iter()
        .map(|(image_name, mut devices_running)| {
            let (mode, excluded, has_override) = effective_policy(&policies, &image_name);
            for entry in &mut devices_running {
                let device_id = entry.get("device_id").and_then(Value::as_str).unwrap_or("");
                entry["excluded"] = json!(excluded.iter().any(|id| id == device_id));
            }
            let any_update_available = devices_running
                .iter()
                .any(|d| d.get("update_available") == Some(&Value::Bool(true)));
            json!({
                "image_name": image_name,
                "mode": mode,
                "has_override": has_override,
                "excluded_device_ids": excluded,
                "any_update_available": any_update_available,
                "devices": devices_running,
            })
        })
        .collect();

    Ok(Json(json!({
        "default_mode": default_mode,
        "images": images,
    })))
}

#[derive(Deserialize)]
struct PolicyInput {
    mode: String,
    #[serde(default)]
    excluded_device_ids: Vec<String>,
}

async fn set_policy(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(image_name): Path<String>,
    Json(payload): Json<PolicyInput>,
) -> Result<Json<Value>, ApiError> {
    if image_name.is_empty() || image_name.len() > 512 {
        return Err(ApiError::bad_request("image_name must be 1-512 characters"));
    }
    if payload.mode != "automatic" && payload.mode != "manual" {
        return Err(ApiError::bad_request("mode must be \"automatic\" or \"manual\""));
    }
    if payload.excluded_device_ids.len() > 1000 || payload.excluded_device_ids.iter().any(|id| id.len() > 36) {
        return Err(ApiError::bad_request("excluded_device_ids is invalid"));
    }
    sqlx::query(
        "INSERT INTO container_update_policies (id, image_name, mode, excluded_device_ids, updated_at) \
         VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (image_name) DO UPDATE SET mode = EXCLUDED.mode, excluded_device_ids = EXCLUDED.excluded_device_ids, updated_at = now()",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&image_name)
    .bind(&payload.mode)
    .bind(json!(payload.excluded_device_ids))
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "image_name": image_name, "mode": payload.mode, "excluded_device_ids": payload.excluded_device_ids })))
}

async fn delete_policy(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(image_name): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    if image_name == "*" {
        return Err(ApiError::bad_request(
            "The fleet-wide default can't be deleted -- set its mode instead",
        ));
    }
    sqlx::query("DELETE FROM container_update_policies WHERE image_name = $1")
        .bind(&image_name)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn container_update_sweep_interval_seconds() -> u64 {
    std::env::var("FLEETVIEW_CONTAINER_UPDATE_SWEEP_SECONDS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&value| value > 0)
        .unwrap_or(30 * 60)
}

/// Queues UPDATE_CONTAINER jobs on the same cadence this sweep runs at:
/// "apply" for every non-excluded device/container whose image resolves to
/// automatic mode, "check" (non-destructive) for manual-mode images, so
/// the dashboard's "update available" status stays reasonably fresh even
/// for images nobody's told to auto-update. Skips a container that
/// already has an UPDATE_CONTAINER job pending or running, the same
/// debounce devices.rs's queue_scheduled_scan uses, so a slow pull/update
/// doesn't pile up duplicate jobs every tick.
async fn sweep_container_updates(pool: &sqlx::PgPool) {
    let devices = match sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices",
    )
    .fetch_all(pool)
    .await
    {
        Ok(devices) => devices,
        Err(error) => {
            tracing::warn!("container update sweep: could not list devices: {error}");
            return;
        }
    };
    let policies = match load_policies(pool).await {
        Ok(policies) => policies,
        Err(error) => {
            tracing::warn!("container update sweep: could not load policies: {error}");
            return;
        }
    };

    for device in &devices {
        if !crate::devices::supports_update_container(device) {
            continue;
        }
        let Some(list) = device.inventory.get("docker_containers").and_then(Value::as_array) else { continue };
        for container in list {
            let (Some(image), Some(container_id)) = (
                container.get("image").and_then(Value::as_str),
                container.get("id").and_then(Value::as_str),
            ) else {
                continue;
            };
            let (mode, excluded, _) = effective_policy(&policies, image);
            if excluded.iter().any(|id| id == &device.id) {
                continue;
            }
            let action = if mode == "automatic" { "apply" } else { "check" };
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT id FROM jobs WHERE device_id = $1 AND type = 'UPDATE_CONTAINER' AND status IN ('pending','running')",
            )
            .bind(&device.id)
            .fetch_optional(pool)
            .await
            .unwrap_or(None);
            if existing.is_some() {
                continue;
            }
            let mut options = json!({ "container_id": container_id, "action": action });
            if action == "apply" {
                options["confirmed"] = json!(true);
            }
            if let Err(error) = insert_job(pool, &Uuid::new_v4().to_string(), &device.id, "UPDATE_CONTAINER", options).await {
                tracing::warn!("container update sweep: device {}: {error}", device.id);
            }
        }
    }
}

pub async fn container_update_sweep_loop(pool: sqlx::PgPool) {
    // Unlike compliance_snapshot_sweep_loop (also runs immediately on
    // startup, but only ever upserts rows, never queues anything), this
    // sweep queues real jobs -- running it the instant the process starts
    // would fire a burst of UPDATE_CONTAINER jobs on every server restart
    // or deploy, with no chance for an admin to review the current
    // policies first. Sleeping first means a short-lived process (every
    // integration test spawns the real binary -- see tests/common/mod.rs)
    // never sweeps at all, and a long-running one waits one full interval
    // before its first sweep, same as any other scheduled maintenance task.
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(container_update_sweep_interval_seconds())).await;
        sweep_container_updates(&pool).await;
    }
}
