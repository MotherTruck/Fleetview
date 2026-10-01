//! Mirrors server/app/deployment.py: approval-gated patch jobs, uploaded
//! custom-package bundles, ad-hoc command execution, network diagnostics,
//! Wake-on-LAN, and remote agent upgrades.
use axum::body::Bytes;
use axum::extract::{Multipart, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use crate::auth::{authenticate_agent, Admin, Operator, Viewer};
use crate::error::ApiError;
use crate::models::Device;
use crate::AppState;

const MAX_FILE: usize = 8 * 1024 * 1024;
const MAX_TOTAL: usize = 16 * 1024 * 1024;
const MAX_COMMAND: usize = 4096;

fn install_dir() -> PathBuf {
    std::env::var("FLEETVIEW_INSTALL_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/opt/fleetview-install"))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/v1/admin/devices/:id/patch-approvals",
            get(list_approvals).put(set_approval),
        )
        .route("/api/v1/admin/devices/:id/deploy-approved-patches", post(deploy_approved))
        .route(
            "/api/v1/admin/devices/:id/patch-schedule",
            get(get_patch_schedule).put(set_patch_schedule),
        )
        .route(
            "/api/v1/admin/custom-packages",
            get(list_bundles).post(upload_bundle),
        )
        .route(
            "/api/v1/admin/custom-packages/:package_id/devices/:device_id/deploy",
            post(deploy_bundle),
        )
        .route("/api/v1/agent/jobs/:id/bundle", get(agent_bundle))
        .route("/api/v1/agent/jobs/:id/bundle/files/:file_id", get(agent_bundle_file))
        .route("/api/v1/admin/devices/:id/run-command", post(run_command))
        .route("/api/v1/admin/devices/:id/network-diagnostic", post(run_network_diagnostic))
        .route("/api/v1/admin/devices/:id/wake", post(wake_device))
        .route("/api/v1/admin/agent-version", get(agent_version))
        .route("/api/v1/admin/devices/:id/upgrade-agent", post(upgrade_agent))
        .route("/install/agent-version", get(install_agent_version))
        .route("/install/linux.sh", get(install_linux_script))
        .route("/install/agent-source.tar.gz", get(install_agent_source))
        .route("/install/agent-source.sha256", get(install_agent_source_checksum))
        .route("/install/agent-linux-amd64", get(install_agent_binary_linux))
        .route("/install/agent-windows-amd64.exe", get(install_agent_binary_windows))
}

// -- version-gate helpers --

fn version_at_least(version: Option<&str>, required: (i32, i32)) -> bool {
    let Some(version) = version else { return false };
    let mut parts = version.split('.').take(2).map(|p| p.parse::<i32>());
    let (Some(Ok(major)), Some(Ok(minor))) = (parts.next(), parts.next()) else {
        return false;
    };
    (major, minor) >= required
}

fn supports_deployment(device: &Device) -> bool {
    version_at_least(device.agent_version.as_deref(), (0, 14))
}
fn supports_run_command(device: &Device) -> bool {
    version_at_least(device.agent_version.as_deref(), (0, 16))
}
// A device below 0.16.0 has no UPGRADE_AGENT case in its job-dispatch
// switch at all, so it cannot be remotely upgraded to the version that
// would let it understand this job type -- that one jump still needs
// scripts/upgrade-agent-in-place.sh (or .ps1) run by hand.
fn supports_agent_upgrade(device: &Device) -> bool {
    supports_run_command(device)
}
fn supports_network_diagnostic(device: &Device) -> bool {
    version_at_least(device.agent_version.as_deref(), (0, 20))
}
// Shipped in the same 0.20.0 release as network diagnostics.
fn supports_wake_on_lan(device: &Device) -> bool {
    supports_network_diagnostic(device)
}

// -- published agent manifest (read once, cached for the process lifetime) --

pub fn published_agent_manifest() -> Option<Value> {
    static MANIFEST: OnceLock<Option<Value>> = OnceLock::new();
    MANIFEST
        .get_or_init(|| {
            let path = install_dir().join("agent-bin").join("manifest.json");
            std::fs::read_to_string(path)
                .ok()
                .and_then(|text| serde_json::from_str(&text).ok())
        })
        .clone()
}

async fn fetch_device(state: &AppState, id: &str) -> Result<Option<Device>, ApiError> {
    Ok(sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.db)
    .await?)
}

fn safe_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    first.is_ascii_alphanumeric() && name.chars().all(|c| c.is_ascii_alphanumeric() || ".-_+:".contains(c))
}

/// Returns (name, version) if this update entry has a safe, well-formed
/// identifier -- entries that don't (e.g. missing a winget ID) are
/// filtered out of the pending-patches view entirely rather than shown
/// broken.
fn patch_key(item: &Value) -> Option<(String, String)> {
    let name = item
        .get("identifier")
        .and_then(Value::as_str)
        .or_else(|| item.get("package").and_then(Value::as_str))?;
    if !safe_package_name(name) {
        return None;
    }
    let version = item.get("available_version").and_then(Value::as_str)?;
    if version.is_empty() || version.len() > 255 {
        return None;
    }
    Some((name.to_string(), version.to_string()))
}

async fn pending_patches(state: &AppState, device: &Device) -> Result<Vec<Value>, ApiError> {
    let approvals = sqlx::query("SELECT package_key, available_version, approved FROM patch_approvals WHERE device_id = $1")
        .bind(&device.id)
        .fetch_all(&state.db)
        .await?;
    let approved: std::collections::HashMap<(String, String), bool> = approvals
        .into_iter()
        .map(|row| {
            let key: String = row.get("package_key");
            let version: String = row.get("available_version");
            let approved: bool = row.get("approved");
            ((key, version), approved)
        })
        .collect();

    let updates = device.available_updates.as_array().cloned().unwrap_or_default();
    let mut result = Vec::new();
    for item in updates {
        let Some((name, version)) = patch_key(&item) else { continue };
        let mut entry = item.as_object().cloned().unwrap_or_default();
        entry.insert("key".to_string(), json!(name));
        entry.insert(
            "approved".to_string(),
            json!(approved.get(&(name.clone(), version.clone())).copied().unwrap_or(false)),
        );
        let supported = device.package_manager.as_deref() != Some("winget")
            || item.get("identifier").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        entry.insert("supported".to_string(), json!(supported));
        result.push(Value::Object(entry));
    }
    Ok(result)
}

async fn approved_snapshot(state: &AppState, device: &Device) -> Result<Vec<Value>, ApiError> {
    let patches = pending_patches(state, device).await?;
    let selected: Vec<&Value> = patches
        .iter()
        .filter(|p| p.get("approved") == Some(&Value::Bool(true)) && p.get("supported") == Some(&Value::Bool(true)))
        .collect();
    if selected.is_empty() {
        return Err(ApiError::conflict("No supported approved patches are pending"));
    }
    if device.package_manager.as_deref() == Some("pacman") && selected.len() != patches.len() {
        return Err(ApiError::conflict(
            "Arch requires approval of every pending package for a full system upgrade",
        ));
    }
    if !matches!(device.package_manager.as_deref(), Some("apt") | Some("pacman") | Some("winget")) {
        return Err(ApiError::bad_request("Patch installation is unsupported on this device"));
    }
    Ok(selected
        .iter()
        .map(|item| json!({ "package": item["key"], "version": item["available_version"] }))
        .collect())
}

async fn active_patch_job(state: &AppState, device_id: &str) -> Result<bool, ApiError> {
    let id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE device_id = $1 AND type IN ('INSTALL_UPDATES','INSTALL_APPROVED_UPDATES') \
         AND status IN ('pending','running')",
    )
    .bind(device_id)
    .fetch_optional(&state.db)
    .await?;
    Ok(id.is_some())
}

/// Called from devices::next_job, mirroring how the Python server calls it
/// from the same place. Best-effort: any failure to queue (no approved
/// patches, an incomplete Arch approval set) is silently skipped, same as
/// the Python version's bare `except HTTPException: return`.
pub async fn queue_scheduled_patch(tx: &mut sqlx::PgConnection, device: &Device) -> Result<(), ApiError> {
    if !supports_deployment(device) {
        return Ok(());
    }
    let schedule = sqlx::query("SELECT interval_hours, next_run_at FROM patch_schedules WHERE device_id = $1")
        .bind(&device.id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(schedule) = schedule else { return Ok(()) };
    let interval_hours: i32 = schedule.get("interval_hours");
    let next_run_at: DateTime<Utc> = schedule.get("next_run_at");
    let now = Utc::now();
    if interval_hours == 0 || next_run_at > now {
        return Ok(());
    }
    let claimed = sqlx::query(
        "UPDATE patch_schedules SET next_run_at = $1 WHERE device_id = $2 AND interval_hours = $3 AND next_run_at = $4",
    )
    .bind(now + Duration::hours(interval_hours as i64))
    .bind(&device.id)
    .bind(interval_hours)
    .bind(next_run_at)
    .execute(&mut *tx)
    .await?;
    if claimed.rows_affected() != 1 {
        return Ok(());
    }
    let has_active: Option<String> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE device_id = $1 AND type IN ('INSTALL_UPDATES','INSTALL_APPROVED_UPDATES') \
         AND status IN ('pending','running')",
    )
    .bind(&device.id)
    .fetch_optional(&mut *tx)
    .await?;
    if has_active.is_some() {
        return Ok(());
    }

    // Inline approved_snapshot's logic against this same transaction
    // instead of the pooled-connection helper above (we're already inside
    // one, and sqlx doesn't let a pooled query run while a transaction on
    // the same connection is open).
    let approvals = sqlx::query("SELECT package_key, available_version, approved FROM patch_approvals WHERE device_id = $1")
        .bind(&device.id)
        .fetch_all(&mut *tx)
        .await?;
    let approved: std::collections::HashMap<(String, String), bool> = approvals
        .into_iter()
        .map(|row| {
            let key: String = row.get("package_key");
            let version: String = row.get("available_version");
            let ok: bool = row.get("approved");
            ((key, version), ok)
        })
        .collect();
    let updates = device.available_updates.as_array().cloned().unwrap_or_default();
    let mut patches = Vec::new();
    for item in &updates {
        let Some((name, version)) = patch_key(item) else { continue };
        let is_approved = approved.get(&(name.clone(), version.clone())).copied().unwrap_or(false);
        let supported = device.package_manager.as_deref() != Some("winget")
            || item.get("identifier").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false);
        patches.push((name, version, is_approved, supported));
    }
    let selected: Vec<&(String, String, bool, bool)> = patches.iter().filter(|(_, _, a, s)| *a && *s).collect();
    if selected.is_empty() {
        return Ok(());
    }
    if device.package_manager.as_deref() == Some("pacman") && selected.len() != patches.len() {
        return Ok(());
    }
    if !matches!(device.package_manager.as_deref(), Some("apt") | Some("pacman") | Some("winget")) {
        return Ok(());
    }
    let options = json!({
        "updates": selected.iter().map(|(n, v, _, _)| json!({"package": n, "version": v})).collect::<Vec<_>>(),
        "scheduled": true,
    });
    crate::models::insert_job(&mut *tx, &Uuid::new_v4().to_string(), &device.id, "INSTALL_APPROVED_UPDATES", options).await?;
    Ok(())
}

// -- patch approvals / schedule --

async fn list_approvals(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Path(id): Path<String>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    Ok(Json(pending_patches(&state, &device).await?))
}

#[derive(Deserialize)]
struct ApprovalInput {
    package: String,
    available_version: String,
    approved: bool,
}

async fn set_approval(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<ApprovalInput>,
) -> Result<Json<Value>, ApiError> {
    if payload.package.is_empty() || payload.package.len() > 255 || payload.available_version.is_empty() || payload.available_version.len() > 255 {
        return Err(ApiError::bad_request("Invalid package/version"));
    }
    let mut tx = state.db.begin().await?;
    let device = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(device) = device else {
        return Err(ApiError::not_found("Device not found"));
    };
    let updates = device.available_updates.as_array().cloned().unwrap_or_default();
    let key = (payload.package.clone(), payload.available_version.clone());
    let keys: std::collections::HashSet<(String, String)> = updates.iter().filter_map(patch_key).collect();
    if !keys.contains(&key) {
        return Err(ApiError::conflict("Patch/version no longer appears in the latest device scan"));
    }
    if device.package_manager.as_deref() == Some("winget") {
        let has_id = updates.iter().any(|item| {
            patch_key(item).as_ref() == Some(&key) && item.get("identifier").and_then(Value::as_str).map(|s| !s.is_empty()).unwrap_or(false)
        });
        if !has_id {
            return Err(ApiError::bad_request("This Windows patch has no winget ID; installation is not supported"));
        }
    }
    sqlx::query(
        "INSERT INTO patch_approvals (device_id, package_key, available_version, approved, updated_at) VALUES ($1, $2, $3, $4, now()) \
         ON CONFLICT (device_id, package_key, available_version) DO UPDATE SET approved = $4, updated_at = now()",
    )
    .bind(&id)
    .bind(&payload.package)
    .bind(&payload.available_version)
    .bind(payload.approved)
    .execute(&mut *tx)
    .await?;
    if !payload.approved {
        let pending_jobs = sqlx::query(
            "SELECT id, options FROM jobs WHERE device_id = $1 AND type = 'INSTALL_APPROVED_UPDATES' AND status = 'pending'",
        )
        .bind(&id)
        .fetch_all(&mut *tx)
        .await?;
        for row in pending_jobs {
            let job_id: String = row.get("id");
            let options: Value = row.get("options");
            let matches = options
                .get("updates")
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter().any(|u| {
                        u.get("package").and_then(Value::as_str) == Some(payload.package.as_str())
                            && u.get("version").and_then(Value::as_str) == Some(payload.available_version.as_str())
                    })
                })
                .unwrap_or(false);
            if matches {
                sqlx::query("UPDATE jobs SET status = 'failed', error = $1, completed_at = $2 WHERE id = $3")
                    .bind("A patch approval was revoked before dispatch; review and queue again")
                    .bind(Utc::now())
                    .bind(&job_id)
                    .execute(&mut *tx)
                    .await?;
            }
        }
    }
    tx.commit().await?;
    Ok(Json(json!({
        "package": payload.package,
        "available_version": payload.available_version,
        "approved": payload.approved,
    })))
}

async fn deploy_approved(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.db.begin().await?;
    let device = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(device) = device else {
        return Err(ApiError::not_found("Device not found"));
    };
    if !supports_deployment(&device) {
        return Err(ApiError::conflict("Upgrade this device's existing agent to 0.14.0 and run a patch scan first"));
    }
    if active_patch_job(&state, &id).await? {
        return Err(ApiError::conflict("A patch job is already pending or running"));
    }
    let updates = approved_snapshot(&state, &device).await?;
    let job_id = Uuid::new_v4().to_string();
    crate::models::insert_job(&mut *tx, &job_id, &id, "INSTALL_APPROVED_UPDATES", json!({ "updates": updates })).await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": job_id, "updates": updates }))))
}

#[derive(Serialize)]
struct ScheduleView {
    interval_hours: i32,
    next_run_at: Option<DateTime<Utc>>,
}

async fn patch_schedule_view(state: &AppState, id: &str) -> Result<ScheduleView, ApiError> {
    let row = sqlx::query("SELECT interval_hours, next_run_at FROM patch_schedules WHERE device_id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    Ok(match row {
        Some(row) => {
            let hours: i32 = row.get("interval_hours");
            let next: DateTime<Utc> = row.get("next_run_at");
            ScheduleView { interval_hours: hours, next_run_at: if hours != 0 { Some(next) } else { None } }
        }
        None => ScheduleView { interval_hours: 0, next_run_at: None },
    })
}

async fn get_patch_schedule(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Path(id): Path<String>,
) -> Result<Json<ScheduleView>, ApiError> {
    if fetch_device(&state, &id).await?.is_none() {
        return Err(ApiError::not_found("Device not found"));
    }
    Ok(Json(patch_schedule_view(&state, &id).await?))
}

#[derive(Deserialize)]
struct ScheduleInput {
    interval_hours: i32,
}

async fn set_patch_schedule(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<ScheduleInput>,
) -> Result<Json<ScheduleView>, ApiError> {
    if !(0..=8760).contains(&payload.interval_hours) {
        return Err(ApiError::bad_request("interval_hours must be between 0 and 8760"));
    }
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    if payload.interval_hours != 0 && !matches!(device.package_manager.as_deref(), Some("apt") | Some("pacman") | Some("winget")) {
        return Err(ApiError::bad_request("Patch scheduling is unsupported on this device"));
    }
    sqlx::query(
        "INSERT INTO patch_schedules (device_id, interval_hours, next_run_at) VALUES ($1, $2, $3) \
         ON CONFLICT (device_id) DO UPDATE SET interval_hours = $2, next_run_at = $3",
    )
    .bind(&id)
    .bind(payload.interval_hours)
    .bind(Utc::now() + Duration::hours(payload.interval_hours as i64))
    .execute(&state.db)
    .await?;
    Ok(Json(patch_schedule_view(&state, &id).await?))
}

// -- custom package bundles --

#[derive(Serialize)]
struct BundleFileView {
    id: String,
    filename: String,
    size: i32,
    sha256: String,
}

#[derive(Serialize)]
struct BundleView {
    id: String,
    name: String,
    platform: String,
    command: String,
    created_at: DateTime<Utc>,
    files: Vec<BundleFileView>,
}

async fn bundle_view(state: &AppState, package_id: &str) -> Result<Option<BundleView>, ApiError> {
    let package = sqlx::query("SELECT id, name, platform, command, created_at FROM custom_packages WHERE id = $1")
        .bind(package_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(package) = package else { return Ok(None) };
    let files = sqlx::query("SELECT id, filename, size, sha256 FROM custom_package_files WHERE package_id = $1")
        .bind(package_id)
        .fetch_all(&state.db)
        .await?;
    Ok(Some(BundleView {
        id: package.get("id"),
        name: package.get("name"),
        platform: package.get("platform"),
        command: package.get("command"),
        created_at: package.get("created_at"),
        files: files
            .into_iter()
            .map(|row| BundleFileView {
                id: row.get("id"),
                filename: row.get("filename"),
                size: row.get("size"),
                sha256: row.get("sha256"),
            })
            .collect(),
    }))
}

async fn list_bundles(State(state): State<Arc<AppState>>, _admin: Admin) -> Result<Json<Vec<Value>>, ApiError> {
    let ids: Vec<String> = sqlx::query_scalar("SELECT id FROM custom_packages ORDER BY created_at DESC")
        .fetch_all(&state.db)
        .await?;
    let mut views = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(view) = bundle_view(&state, &id).await? {
            views.push(serde_json::to_value(view).unwrap());
        }
    }
    Ok(Json(views))
}

fn safe_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > 200 || name == "." || name == ".." {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    first.is_ascii_alphanumeric()
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == ' ' || c == '-')
}

async fn upload_bundle(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, ApiError> {
    let mut name = None;
    let mut platform = None;
    let mut command = None;
    let mut files: Vec<(String, Bytes)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut total = 0usize;

    while let Some(field) = multipart.next_field().await.map_err(|e| ApiError::bad_request(e.to_string()))? {
        match field.name().unwrap_or("").to_string().as_str() {
            "name" => name = Some(field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?),
            "platform" => platform = Some(field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?),
            "command" => command = Some(field.text().await.map_err(|e| ApiError::bad_request(e.to_string()))?),
            "files" => {
                let filename = field.file_name().unwrap_or("").to_string();
                if !safe_filename(&filename) || seen.contains(&filename) {
                    return Err(ApiError::bad_request("Use unique plain filenames without directories"));
                }
                let blob = field.bytes().await.map_err(|e| ApiError::bad_request(e.to_string()))?;
                if blob.is_empty() || blob.len() > MAX_FILE {
                    return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Each file must be nonempty and at most 8 MiB"));
                }
                total += blob.len();
                if total > MAX_TOTAL {
                    return Err(ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "Files total at most 16 MiB"));
                }
                seen.insert(filename.clone());
                files.push((filename, blob));
                if files.len() > 5 {
                    return Err(ApiError::bad_request("Upload between one and five files"));
                }
            }
            _ => {}
        }
    }

    let name = name.unwrap_or_default().trim().to_string();
    let platform = platform.unwrap_or_default();
    let command = command.unwrap_or_default().trim().to_string();
    if name.is_empty() || name.len() > 255 || !matches!(platform.as_str(), "linux" | "windows") || command.is_empty() || command.len() > 4096 {
        return Err(ApiError::bad_request("Name, platform and install command are required"));
    }
    if files.is_empty() || files.len() > 5 {
        return Err(ApiError::bad_request("Upload between one and five files"));
    }

    let package_id = Uuid::new_v4().to_string();
    let mut tx = state.db.begin().await?;
    sqlx::query("INSERT INTO custom_packages (id, name, platform, command, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(&package_id)
        .bind(&name)
        .bind(&platform)
        .bind(&command)
        .execute(&mut *tx)
        .await?;
    for (filename, blob) in &files {
        let sha256 = hex::encode(Sha256::digest(blob));
        sqlx::query(
            "INSERT INTO custom_package_files (id, package_id, filename, content, size, sha256) VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&package_id)
        .bind(filename)
        .bind(blob.as_ref())
        .bind(blob.len() as i32)
        .bind(sha256)
        .execute(&mut *tx)
        .await?;
    }
    let actor = admin.0.user().map(|u| u.username.as_str()).unwrap_or("bootstrap");
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, 'custom_package_created', $2, $3, now())")
        .bind(actor)
        .bind(&name)
        .bind(format!("{platform}, {} file(s)", files.len()))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let view = bundle_view(&state, &package_id).await?.unwrap();
    Ok((StatusCode::CREATED, Json(view)))
}

#[derive(Deserialize, Default)]
struct ConfirmedAction {
    #[serde(default)]
    confirmed: bool,
}

async fn deploy_bundle(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path((package_id, device_id)): Path<(String, String)>,
    body: Option<Json<ConfirmedAction>>,
) -> Result<impl IntoResponse, ApiError> {
    let payload = body.map(|Json(p)| p).unwrap_or_default();
    let package = sqlx::query("SELECT id, platform, name FROM custom_packages WHERE id = $1")
        .bind(&package_id)
        .fetch_optional(&state.db)
        .await?;
    let mut tx = state.db.begin().await?;
    let device = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(&device_id)
    .fetch_optional(&mut *tx)
    .await?;
    let (Some(package), Some(device)) = (package, device) else {
        return Err(ApiError::not_found("Custom package or device not found"));
    };
    if !payload.confirmed {
        return Err(ApiError::bad_request("Custom package deployment requires explicit confirmation"));
    }
    if !supports_deployment(&device) {
        return Err(ApiError::conflict("Upgrade this device's existing agent to 0.14.0 and run a patch scan first"));
    }
    let package_platform: String = package.get("platform");
    if (device.platform == "windows") != (package_platform == "windows") {
        return Err(ApiError::bad_request("Custom package platform does not match the target"));
    }
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE device_id = $1 AND type = 'INSTALL_CUSTOM_PACKAGE' AND status IN ('pending','running')",
    )
    .bind(&device_id)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Err(ApiError::conflict("A custom install is already pending or running"));
    }
    let package_name: String = package.get("name");
    let job_id = Uuid::new_v4().to_string();
    crate::models::insert_job(&mut *tx, &job_id, &device_id, "INSTALL_CUSTOM_PACKAGE", json!({ "package_id": package_id, "name": package_name })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": job_id, "device_id": device_id, "package": package_name })),
    ))
}

async fn authorized_bundle_job(state: &AppState, device_id: &str, authorization: &str, job_id: &str) -> Result<String, ApiError> {
    let device = authenticate_agent(state, device_id, authorization).await?;
    let job = sqlx::query("SELECT device_id, type, status, options FROM jobs WHERE id = $1")
        .bind(job_id)
        .fetch_optional(&state.db)
        .await?;
    let not_found = || ApiError::not_found("Running custom install job not found");
    let Some(job) = job else { return Err(not_found()) };
    let job_device_id: String = job.get("device_id");
    let job_type: String = job.get("type");
    let job_status: String = job.get("status");
    if job_device_id != device.id || job_type != "INSTALL_CUSTOM_PACKAGE" || job_status != "running" {
        return Err(not_found());
    }
    let options: Value = job.get("options");
    let package_id = options.get("package_id").and_then(Value::as_str).ok_or_else(not_found)?;
    let exists: Option<String> = sqlx::query_scalar("SELECT id FROM custom_packages WHERE id = $1")
        .bind(package_id)
        .fetch_optional(&state.db)
        .await?;
    exists.ok_or_else(|| ApiError::not_found("Custom package not found"))?;
    Ok(package_id.to_string())
}

async fn agent_bundle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Result<Json<BundleView>, ApiError> {
    let device_id = headers.get("x-device-id").and_then(|v| v.to_str().ok()).unwrap_or("");
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let package_id = authorized_bundle_job(&state, device_id, authorization, &job_id).await?;
    Ok(Json(bundle_view(&state, &package_id).await?.unwrap()))
}

async fn agent_bundle_file(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((job_id, file_id)): Path<(String, String)>,
) -> Result<impl IntoResponse, ApiError> {
    let device_id = headers.get("x-device-id").and_then(|v| v.to_str().ok()).unwrap_or("");
    let authorization = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let package_id = authorized_bundle_job(&state, device_id, authorization, &job_id).await?;
    let row = sqlx::query("SELECT package_id, content FROM custom_package_files WHERE id = $1")
        .bind(&file_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(row) = row else {
        return Err(ApiError::not_found("File not found"));
    };
    let file_package_id: String = row.get("package_id");
    if file_package_id != package_id {
        return Err(ApiError::not_found("File not found"));
    }
    let content: Vec<u8> = row.get("content");
    Ok(([("content-type", "application/octet-stream")], content))
}

// -- run-command / network diagnostic / wake / upgrade --

#[derive(Deserialize)]
struct RunCommandInput {
    command: String,
    confirmed: bool,
}

async fn run_command(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<String>,
    Json(payload): Json<RunCommandInput>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.command.is_empty() || payload.command.len() > MAX_COMMAND {
        return Err(ApiError::bad_request("Invalid command"));
    }
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    if !payload.confirmed {
        return Err(ApiError::bad_request("Command execution requires explicit confirmation"));
    }
    if !supports_run_command(&device) {
        return Err(ApiError::conflict("Upgrade this device's existing agent to 0.16.0 and run a patch scan first"));
    }
    let job_id = Uuid::new_v4().to_string();
    let mut tx = state.db.begin().await?;
    crate::models::insert_job(&mut *tx, &job_id, &id, "RUN_COMMAND", json!({ "command": payload.command, "confirmed": true })).await?;
    let actor = admin.0.user().map(|u| u.username.as_str()).unwrap_or("bootstrap");
    // AccountAudit.details is VARCHAR(255); truncate, or Postgres rejects
    // the insert outright for any command longer than that.
    let details: String = payload.command.chars().take(255).collect();
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, 'run_command', $2, $3, now())")
        .bind(actor)
        .bind(&device.hostname)
        .bind(details)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": job_id, "device_id": id }))))
}

fn safe_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 255 {
        return false;
    }
    let bytes = target.as_bytes();
    let is_alnum = |b: u8| b.is_ascii_alphanumeric();
    if !is_alnum(bytes[0]) {
        return false;
    }
    if bytes.len() == 1 {
        return true;
    }
    if !is_alnum(*bytes.last().unwrap()) {
        return false;
    }
    bytes.iter().all(|&b| is_alnum(b) || b == b'.' || b == b'-')
}

#[derive(Deserialize)]
struct NetworkDiagnosticInput {
    tool: String,
    target: String,
    port: Option<i32>,
}

async fn run_network_diagnostic(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<NetworkDiagnosticInput>,
) -> Result<impl IntoResponse, ApiError> {
    if !matches!(payload.tool.as_str(), "ping" | "traceroute" | "dns" | "port_check") {
        return Err(ApiError::bad_request("Invalid diagnostic tool"));
    }
    if !safe_target(&payload.target) {
        return Err(ApiError::bad_request("Invalid target"));
    }
    if let Some(port) = payload.port {
        if !(1..=65535).contains(&port) {
            return Err(ApiError::bad_request("Invalid port"));
        }
    }
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    if payload.tool == "port_check" && payload.port.is_none() {
        return Err(ApiError::bad_request("port_check requires a port"));
    }
    if !supports_network_diagnostic(&device) {
        return Err(ApiError::conflict("Upgrade this device's existing agent to 0.20.0 first"));
    }
    let job_id = Uuid::new_v4().to_string();
    crate::models::insert_job(&state.db, &job_id, &id, "NETWORK_DIAGNOSTIC", json!({ "tool": payload.tool, "target": payload.target, "port": payload.port })).await?;
    Ok((StatusCode::CREATED, Json(json!({ "id": job_id, "device_id": id }))))
}

#[derive(Deserialize)]
struct WakeOnLanInput {
    relay_device_id: String,
}

async fn wake_device(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<WakeOnLanInput>,
) -> Result<impl IntoResponse, ApiError> {
    if payload.relay_device_id.is_empty() || payload.relay_device_id.len() > 36 {
        return Err(ApiError::bad_request("Invalid relay device"));
    }
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    let mac_addresses = device.inventory.get("mac_addresses").and_then(Value::as_array).cloned().unwrap_or_default();
    let Some(mac) = mac_addresses.first().and_then(Value::as_str) else {
        return Err(ApiError::conflict(
            "This device has no known MAC address yet; it needs at least one inventory scan first",
        ));
    };
    let Some(relay) = fetch_device(&state, &payload.relay_device_id).await? else {
        return Err(ApiError::not_found("Relay device not found"));
    };
    if relay.id == device.id {
        return Err(ApiError::bad_request("The relay must be a different, currently online device"));
    }
    if relay.last_seen < Utc::now() - Duration::minutes(2) {
        return Err(ApiError::conflict("The relay device must currently be online"));
    }
    if !supports_wake_on_lan(&relay) {
        return Err(ApiError::conflict("The relay device's agent must be 0.20.0 or later"));
    }
    let job_id = Uuid::new_v4().to_string();
    crate::models::insert_job(&state.db, &job_id, &relay.id, "WAKE_ON_LAN", json!({ "mac": mac, "target_device_id": device.id })).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": job_id, "relay_device_id": relay.id, "mac": mac })),
    ))
}

async fn agent_version(_viewer: Viewer) -> Result<Json<Value>, ApiError> {
    published_agent_manifest().map(Json).ok_or_else(|| {
        ApiError::not_found("No published agent binaries are available on this server")
    })
}

async fn upgrade_agent(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let mut tx = state.db.begin().await?;
    let device = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(device) = device else {
        return Err(ApiError::not_found("Device not found"));
    };
    let Some(manifest) = published_agent_manifest() else {
        return Err(ApiError::conflict("This server has no published agent binaries built in"));
    };
    if !matches!(device.platform.as_str(), "linux" | "windows") {
        return Err(ApiError::bad_request("Agent upgrade is unsupported on this device's platform"));
    }
    if !supports_agent_upgrade(&device) {
        return Err(ApiError::conflict(
            "Upgrade this device's existing agent to 0.16.0 with scripts/upgrade-agent-in-place.sh \
             (or .ps1) first; remote upgrades work from there onward",
        ));
    }
    let manifest_version = manifest.get("version").and_then(Value::as_str).unwrap_or("");
    if device.agent_version.as_deref() == Some(manifest_version) {
        return Err(ApiError::conflict(format!(
            "This device already reports agent version {manifest_version}"
        )));
    }
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE device_id = $1 AND type = 'UPGRADE_AGENT' AND status IN ('pending','running')",
    )
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Err(ApiError::conflict("An agent upgrade is already pending or running"));
    }
    let platform_key = if device.platform == "windows" { "windows_amd64" } else { "linux_amd64" };
    let Some(asset) = manifest.get(platform_key) else {
        return Err(ApiError::conflict(format!("No published agent binary for {platform_key}")));
    };
    let job_id = Uuid::new_v4().to_string();
    crate::models::insert_job(&mut *tx, &job_id, &id, "UPGRADE_AGENT", json!({
        "version": manifest_version,
        "sha256": asset.get("sha256"),
        "url": asset.get("path"),
    })).await?;
    tx.commit().await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": job_id, "device_id": id, "version": manifest_version })),
    ))
}

// -- unauthenticated install/* static endpoints --

async fn install_agent_version() -> Result<Json<Value>, ApiError> {
    published_agent_manifest()
        .map(Json)
        .ok_or_else(|| ApiError::not_found("Published agent binaries are not available"))
}

async fn read_install_file(name: &str) -> Result<Vec<u8>, ApiError> {
    tokio::fs::read(install_dir().join(name))
        .await
        .map_err(|_| ApiError::not_found("Not available on this server"))
}

async fn install_linux_script() -> Result<impl IntoResponse, ApiError> {
    let data = read_install_file("install-linux.sh").await.map_err(|_| ApiError::not_found("Linux installer is not available"))?;
    Ok((
        [
            ("content-type", "text/x-shellscript"),
            ("content-disposition", "attachment; filename=\"install-fleetview-agent.sh\""),
        ],
        data,
    ))
}

async fn install_agent_source() -> Result<impl IntoResponse, ApiError> {
    let data = read_install_file("agent-source.tar.gz")
        .await
        .map_err(|_| ApiError::not_found("Agent source bundle is not available"))?;
    Ok((
        [
            ("content-type", "application/gzip"),
            ("content-disposition", "attachment; filename=\"fleetview-agent-source.tar.gz\""),
        ],
        data,
    ))
}

async fn install_agent_source_checksum() -> Result<impl IntoResponse, ApiError> {
    let data = read_install_file("agent-source.sha256")
        .await
        .map_err(|_| ApiError::not_found("Agent source checksum is not available"))?;
    let text = String::from_utf8_lossy(&data).trim().to_string();
    Ok(text)
}

async fn install_agent_binary_linux() -> Result<impl IntoResponse, ApiError> {
    let data = tokio::fs::read(install_dir().join("agent-bin").join("linux-amd64").join("fleetview-agent"))
        .await
        .map_err(|_| ApiError::not_found("Published Linux agent binary is not available"))?;
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("content-disposition", "attachment; filename=\"fleetview-agent\""),
        ],
        data,
    ))
}

async fn install_agent_binary_windows() -> Result<impl IntoResponse, ApiError> {
    let data = tokio::fs::read(install_dir().join("agent-bin").join("windows-amd64").join("fleetview-agent.exe"))
        .await
        .map_err(|_| ApiError::not_found("Published Windows agent binary is not available"))?;
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("content-disposition", "attachment; filename=\"fleetview-agent.exe\""),
        ],
        data,
    ))
}
