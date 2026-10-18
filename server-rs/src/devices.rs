//! Mirrors server/app/main.py's device/agent/job/fleet-settings core:
//! device_view and friends, the agent-facing report/metrics/vulnerabilities/
//! heartbeat/settings/jobs endpoints, and the admin device/jobs/fleet-settings
//! endpoints. Reports history, package catalog, and the install/* static
//! endpoints land in a later increment (they depend on deployment.py's
//! published_agent_manifest, ported alongside the rest of that file).
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sqlx::{PgPool, Row};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use uuid::Uuid;

use crate::auth::{authenticate_agent, Admin, Operator, Viewer};
use crate::error::ApiError;
use crate::models::Device;
use crate::security::verify_password;
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/agent/report", post(report))
        .route("/api/v1/agent/vulnerabilities", post(report_vulnerabilities))
        .route("/api/v1/agent/metrics", post(report_metrics))
        .route("/api/v1/agent/heartbeat", post(heartbeat))
        .route("/api/v1/agent/settings", get(get_agent_settings))
        .route("/api/v1/agent/uninstall/verify", post(verify_agent_uninstall))
        .route("/api/v1/agent/jobs/next", get(next_job))
        .route("/api/v1/agent/jobs/:id/result", post(complete_job))
        .route("/api/v1/admin/devices", get(list_devices))
        .route(
            "/api/v1/admin/devices/:id",
            get(get_device).delete(delete_device),
        )
        .route("/api/v1/admin/devices/:id/settings", put(update_device_settings))
        .route("/api/v1/admin/devices/:id/tags", put(update_device_tags))
        .route("/api/v1/admin/devices/:id/metrics", get(get_device_metrics))
        .route("/api/v1/admin/devices/:id/container-metrics", get(get_device_container_metrics))
        .route(
            "/api/v1/admin/devices/:id/vulnerability-schedule",
            get(get_scan_schedule).put(set_scan_schedule),
        )
        .route("/api/v1/admin/settings", get(get_fleet_settings_endpoint).put(update_fleet_settings))
        .route("/api/v1/admin/jobs", get(list_jobs))
        .route("/api/v1/admin/devices/:id/jobs", post(create_job))
}

fn header(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string()
}

async fn authenticate_from_headers(state: &AppState, headers: &HeaderMap) -> Result<Device, ApiError> {
    let device_id = header(headers, "x-device-id");
    let authorization = header(headers, "authorization");
    authenticate_agent(state, &device_id, &authorization).await
}

// -- shared view helpers (device_view, job_view, public_agent_settings) --

fn as_object(value: &Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap_or_default()
}

/// Unix daemons conventionally add a trailing "d" to the thing they run
/// (sshd for ssh, mysqld for mysql) while the package name usually
/// doesn't, so stripping it catches the single most common package-vs-
/// process naming mismatch without a hardcoded name table.
fn process_match_candidates(process: &str) -> HashSet<String> {
    let mut candidates = HashSet::new();
    candidates.insert(process.to_string());
    if process.len() >= 4 && process.ends_with('d') {
        candidates.insert(process[..process.len() - 1].to_string());
    }
    candidates
}

fn annotate_exposure(vulnerabilities: &[Value], listening_ports: &[Value]) -> Vec<Value> {
    let mut ports_by_candidate: HashMap<String, Vec<Value>> = HashMap::new();
    for port in listening_ports {
        let process = port
            .get("process")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim()
            .to_lowercase();
        if process.is_empty() || process == "unknown" {
            continue;
        }
        for candidate in process_match_candidates(&process) {
            ports_by_candidate.entry(candidate).or_default().push(port.clone());
        }
    }

    vulnerabilities
        .iter()
        .map(|finding| {
            let package = finding
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or("")
                .trim()
                .to_lowercase();
            let mut matches = Vec::new();
            if !package.is_empty() {
                for (candidate, ports) in &ports_by_candidate {
                    if candidate.len() >= 3 && (package.contains(candidate.as_str()) || candidate.contains(package.as_str())) {
                        matches.extend(ports.iter().cloned());
                    }
                }
            }
            let mut annotated = as_object(finding);
            if !matches.is_empty() {
                annotated.insert("exposure".to_string(), json!("listening"));
                let mut details: Vec<String> = matches
                    .iter()
                    .map(|p| {
                        let protocol = p.get("protocol").and_then(Value::as_str).unwrap_or("tcp");
                        let port = p.get("port").cloned().unwrap_or(Value::Null);
                        format!("{protocol}/{port}")
                    })
                    .collect();
                details.sort();
                details.dedup();
                annotated.insert("exposure_detail".to_string(), json!(details));
            } else {
                annotated.insert("exposure".to_string(), json!("unknown"));
                annotated.insert("exposure_detail".to_string(), json!([]));
            }
            Value::Object(annotated)
        })
        .collect()
}

pub fn public_agent_settings(inventory: &Value, default_metrics: i32, default_inventory: i32) -> Value {
    let stored = inventory.get("_agent_settings").cloned().unwrap_or(json!({}));
    let stored = if stored.is_object() { stored } else { json!({}) };
    json!({
        "metrics_interval_seconds": stored.get("metrics_interval_seconds").cloned().unwrap_or(json!(default_metrics)),
        "inventory_interval_seconds": stored.get("inventory_interval_seconds").cloned().unwrap_or(json!(default_inventory)),
        "gpu_monitoring_enabled": stored.get("gpu_monitoring_enabled").cloned().unwrap_or(json!(true)),
        "docker_inventory_enabled": stored.get("docker_inventory_enabled").cloned().unwrap_or(json!(true)),
        "uninstall_code_required": !stored.get("uninstall_code_hash").and_then(Value::as_str).unwrap_or("").is_empty(),
    })
}

struct FleetSettings {
    default_metrics_interval_seconds: i32,
    default_inventory_interval_seconds: i32,
}

async fn get_fleet_settings(state: &AppState) -> Result<FleetSettings, ApiError> {
    let row = sqlx::query(
        "SELECT default_metrics_interval_seconds, default_inventory_interval_seconds FROM fleet_settings WHERE id = 1",
    )
    .fetch_optional(&state.db)
    .await?;
    if let Some(row) = row {
        return Ok(FleetSettings {
            default_metrics_interval_seconds: row.get("default_metrics_interval_seconds"),
            default_inventory_interval_seconds: row.get("default_inventory_interval_seconds"),
        });
    }
    // Concurrent requests can both see no row and both try to create it;
    // the loser's INSERT hits the primary key and falls back to a plain
    // read instead of erroring, since by then the winner's row exists.
    sqlx::query(
        "INSERT INTO fleet_settings (id, default_metrics_interval_seconds, default_inventory_interval_seconds, updated_at) \
         VALUES (1, 60, 900, now()) ON CONFLICT (id) DO NOTHING",
    )
    .execute(&state.db)
    .await?;
    let row = sqlx::query(
        "SELECT default_metrics_interval_seconds, default_inventory_interval_seconds FROM fleet_settings WHERE id = 1",
    )
    .fetch_one(&state.db)
    .await?;
    Ok(FleetSettings {
        default_metrics_interval_seconds: row.get("default_metrics_interval_seconds"),
        default_inventory_interval_seconds: row.get("default_inventory_interval_seconds"),
    })
}

fn device_view(device: &Device, fleet: &FleetSettings, hub: &crate::live::LiveHub, include_packages: bool) -> Value {
    let online = device.last_seen >= Utc::now() - Duration::minutes(2);
    let inventory = &device.inventory;
    let security = inventory.get("_security").cloned().unwrap_or(json!({}));
    let patching = inventory.get("_patching").cloned().unwrap_or(json!({}));
    let monitoring = inventory.get("_monitoring").cloned().unwrap_or(json!({}));
    let agent_settings = public_agent_settings(
        inventory,
        fleet.default_metrics_interval_seconds,
        fleet.default_inventory_interval_seconds,
    );
    let public_inventory: Map<String, Value> = as_object(inventory)
        .into_iter()
        .filter(|(key, _)| !key.starts_with('_'))
        .collect();

    let listening_ports = security.get("listening_ports").and_then(Value::as_array).cloned().unwrap_or_default();
    let vulnerabilities_raw = security.get("vulnerabilities").and_then(Value::as_array).cloned().unwrap_or_default();
    let vulnerabilities = annotate_exposure(&vulnerabilities_raw, &listening_ports);

    let mut severity_counts: Map<String, Value> = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        .iter()
        .map(|s| (s.to_string(), json!(0)))
        .collect();
    let mut exposed_count = 0;
    for finding in &vulnerabilities {
        let severity = finding.get("severity").and_then(Value::as_str).unwrap_or("UNKNOWN").to_uppercase();
        let key = if severity_counts.contains_key(&severity) { severity } else { "UNKNOWN".to_string() };
        let current = severity_counts.get(&key).and_then(Value::as_i64).unwrap_or(0);
        severity_counts.insert(key, json!(current + 1));
        if finding.get("exposure").and_then(Value::as_str) == Some("listening") {
            exposed_count += 1;
        }
    }

    let installed_packages = device.installed_packages.as_array().cloned().unwrap_or_default();
    let available_updates = device.available_updates.as_array().cloned().unwrap_or_default();

    let mut result = json!({
        "id": device.id,
        "hostname": device.hostname,
        "display_name": device.display_name,
        "platform": device.platform,
        "os_name": device.os_name,
        "os_version": device.os_version,
        "architecture": device.architecture,
        "package_manager": device.package_manager,
        "agent_version": device.agent_version,
        "enrolled_at": device.enrolled_at,
        "last_seen": device.last_seen,
        "last_scan_at": device.last_scan_at,
        "online": online,
        "live": hub.is_agent_live(&device.id),
        "update_count": device.update_count,
        "security_update_count": device.security_update_count,
        "inventory": public_inventory,
        "installed_package_count": installed_packages.len(),
        "vulnerability_count": vulnerabilities.len(),
        "vulnerability_severity_counts": severity_counts,
        "vulnerability_exposed_count": exposed_count,
        "last_vulnerability_scan_at": security.get("scanned_at"),
        "vulnerability_scanner": security.get("scanner"),
        "vulnerability_scanner_version": security.get("scanner_version"),
        "last_patched_at": patching.get("last_patched_at"),
        "metrics": monitoring.get("current"),
        "agent_settings": agent_settings,
        "tags": inventory.get("_tags").cloned().unwrap_or_else(|| json!([])),
    });
    if include_packages {
        let obj = result.as_object_mut().unwrap();
        obj.insert("installed_packages".to_string(), json!(installed_packages));
        obj.insert("available_updates".to_string(), json!(available_updates));
        obj.insert("vulnerabilities".to_string(), json!(vulnerabilities));
        obj.insert("listening_ports".to_string(), json!(listening_ports));
    }
    result
}

#[derive(sqlx::FromRow)]
struct JobRow {
    id: String,
    device_id: String,
    #[sqlx(rename = "type")]
    job_type: String,
    status: String,
    options: Value,
    created_at: DateTime<Utc>,
    claimed_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    exit_code: Option<i32>,
    output: Option<String>,
    error: Option<String>,
}

fn job_view(job: &JobRow, redact: bool) -> Value {
    // RUN_COMMAND's options/output are effectively a secrets vault
    // (whatever an admin typed or the command printed) -- viewers can see
    // that a command ran, not what it was or what it printed.
    let (options, output, error) = if redact && job.job_type == "RUN_COMMAND" {
        (json!({}), None, None)
    } else {
        (job.options.clone(), job.output.clone(), job.error.clone())
    };
    json!({
        "id": job.id,
        "device_id": job.device_id,
        "type": job.job_type,
        "status": job.status,
        "options": options,
        "created_at": job.created_at,
        "claimed_at": job.claimed_at,
        "completed_at": job.completed_at,
        "exit_code": job.exit_code,
        "output": output,
        "error": error,
    })
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

/// Piggybacks on the patch and vulnerability report endpoints instead of
/// running on a schedule, so it costs one extra SELECT (and, once a day
/// per device, one INSERT) on requests the agent is already making.
async fn record_compliance_snapshot(
    tx: &mut sqlx::PgConnection,
    device: &Device,
) -> Result<(), ApiError> {
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let existing: Option<i32> = sqlx::query_scalar(
        "SELECT id FROM compliance_snapshots WHERE device_id = $1 AND snapshot_date = $2",
    )
    .bind(&device.id)
    .bind(&today)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Ok(());
    }
    let security = device.inventory.get("_security").cloned().unwrap_or(json!({}));
    let vulnerabilities = security.get("vulnerabilities").and_then(Value::as_array).cloned().unwrap_or_default();
    let critical = vulnerabilities
        .iter()
        .filter(|v| v.get("severity").and_then(Value::as_str).unwrap_or("").to_uppercase() == "CRITICAL")
        .count() as i32;
    let high = vulnerabilities
        .iter()
        .filter(|v| v.get("severity").and_then(Value::as_str).unwrap_or("").to_uppercase() == "HIGH")
        .count() as i32;
    let online = device.last_seen >= Utc::now() - Duration::minutes(2);
    sqlx::query(
        "INSERT INTO compliance_snapshots \
         (device_id, snapshot_date, update_count, security_update_count, vulnerability_count, \
          critical_vulnerability_count, high_vulnerability_count, online, recorded_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())",
    )
    .bind(&device.id)
    .bind(&today)
    .bind(device.update_count)
    .bind(device.security_update_count)
    .bind(vulnerabilities.len() as i32)
    .bind(critical)
    .bind(high)
    .bind(online)
    .execute(&mut *tx)
    .await?;
    Ok(())
}

fn scan_supported(device: &Device) -> bool {
    let os_name = device.os_name.as_deref().unwrap_or("").to_lowercase();
    device.package_manager.as_deref() == Some("pacman")
        || (device.package_manager.as_deref() == Some("apt") && os_name.contains("debian"))
}

/// Atomic due-time claim prevents duplicate scheduled jobs across workers.
async fn queue_scheduled_scan(tx: &mut sqlx::PgConnection, device: &Device) -> Result<(), ApiError> {
    if !scan_supported(device) {
        return Ok(());
    }
    let now = Utc::now();
    let schedule = sqlx::query("SELECT interval_hours, next_run_at FROM vulnerability_schedules WHERE device_id = $1")
        .bind(&device.id)
        .fetch_optional(&mut *tx)
        .await?;
    let Some(schedule) = schedule else { return Ok(()) };
    let interval_hours: i32 = schedule.get("interval_hours");
    let next_run_at: DateTime<Utc> = schedule.get("next_run_at");
    if interval_hours == 0 || next_run_at > now {
        return Ok(());
    }
    let claimed = sqlx::query(
        "UPDATE vulnerability_schedules SET next_run_at = $1 \
         WHERE device_id = $2 AND next_run_at = $3 AND interval_hours = $4",
    )
    .bind(now + Duration::hours(interval_hours as i64))
    .bind(&device.id)
    .bind(next_run_at)
    .bind(interval_hours)
    .execute(&mut *tx)
    .await?;
    if claimed.rows_affected() != 1 {
        return Ok(());
    }
    let active: Option<String> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE device_id = $1 AND type = 'SCAN_VULNERABILITIES' AND status IN ('pending','running')",
    )
    .bind(&device.id)
    .fetch_optional(&mut *tx)
    .await?;
    if active.is_none() {
        crate::models::insert_job(&mut *tx, &Uuid::new_v4().to_string(), &device.id, "SCAN_VULNERABILITIES", json!({"scheduled": true})).await?;
    }
    Ok(())
}

// -- agent-facing endpoints --

#[derive(Deserialize)]
struct DeviceReportPayload {
    hostname: String,
    #[serde(default = "default_platform")]
    platform: String,
    os_name: Option<String>,
    os_version: Option<String>,
    architecture: Option<String>,
    package_manager: Option<String>,
    agent_version: String,
    #[serde(default)]
    inventory: Map<String, Value>,
    #[serde(default)]
    installed_packages: Vec<Value>,
    #[serde(default)]
    available_updates: Vec<Value>,
    scanned_at: DateTime<Utc>,
}

fn default_platform() -> String {
    "linux".to_string()
}

async fn report(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<DeviceReportPayload>,
) -> Result<StatusCode, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    if payload.hostname.is_empty() || payload.hostname.len() > 255 {
        return Err(ApiError::bad_request("Invalid hostname"));
    }

    let mut inventory = payload.inventory.clone();
    for key in ["_security", "_patching", "_monitoring", "_agent_settings"] {
        if let Some(value) = device.inventory.get(key) {
            if !value.is_null() {
                inventory.insert(key.to_string(), value.clone());
            }
        }
    }
    let update_count = payload.available_updates.len() as i32;
    let security_update_count = payload
        .available_updates
        .iter()
        .filter(|u| u.get("security_update").and_then(Value::as_bool) == Some(true))
        .count() as i32;

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE devices SET hostname=$1, platform=$2, os_name=$3, os_version=$4, architecture=$5, \
         package_manager=$6, agent_version=$7, inventory=$8, installed_packages=$9, available_updates=$10, \
         update_count=$11, security_update_count=$12, last_seen=$13, last_scan_at=$14 WHERE id=$15",
    )
    .bind(&payload.hostname)
    .bind(&payload.platform)
    .bind(&payload.os_name)
    .bind(&payload.os_version)
    .bind(&payload.architecture)
    .bind(&payload.package_manager)
    .bind(&payload.agent_version)
    .bind(Value::Object(inventory))
    .bind(json!(payload.installed_packages))
    .bind(json!(payload.available_updates))
    .bind(update_count)
    .bind(security_update_count)
    .bind(Utc::now())
    .bind(payload.scanned_at)
    .bind(&device.id)
    .execute(&mut *tx)
    .await?;

    let mut updated = device;
    updated.update_count = update_count;
    updated.security_update_count = security_update_count;
    updated.last_seen = Utc::now();
    record_compliance_snapshot(&mut tx, &updated).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct VulnerabilityReportPayload {
    #[serde(default = "unknown")]
    scanner: String,
    #[serde(default = "unknown")]
    scanner_version: String,
    scanned_at: DateTime<Utc>,
    #[serde(default)]
    vulnerabilities: Vec<Value>,
    #[serde(default)]
    listening_ports: Vec<Value>,
}

fn unknown() -> String {
    "unknown".to_string()
}

async fn report_vulnerabilities(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<VulnerabilityReportPayload>,
) -> Result<StatusCode, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    let mut inventory = as_object(&device.inventory);
    inventory.insert(
        "_security".to_string(),
        json!({
            "scanner": payload.scanner,
            "scanner_version": payload.scanner_version,
            "scanned_at": payload.scanned_at,
            "vulnerabilities": payload.vulnerabilities,
            "listening_ports": payload.listening_ports,
        }),
    );
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE devices SET inventory = $1, last_seen = $2 WHERE id = $3")
        .bind(Value::Object(inventory.clone()))
        .bind(Utc::now())
        .bind(&device.id)
        .execute(&mut *tx)
        .await?;
    let mut updated = device;
    updated.inventory = Value::Object(inventory);
    updated.last_seen = Utc::now();
    record_compliance_snapshot(&mut tx, &updated).await?;
    tx.commit().await?;

    // Fire-and-forget: NVD can be slow or rate-limited, and must never add
    // latency to the agent's own report request.
    let db = state.db.clone();
    let device_id = updated.id.clone();
    let scanned_at = payload.scanned_at;
    tokio::spawn(async move {
        crate::cve_enrichment::enrich_device_vulnerabilities(db, device_id, scanned_at).await;
    });

    Ok(StatusCode::NO_CONTENT)
}

/// Truncates to at most `max` chars (not bytes -- a byte-index slice can
/// panic mid multi-byte UTF-8 character), for a free-text agent-reported
/// value going into a bounded VARCHAR column.
fn truncate_chars(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[derive(Deserialize, Serialize)]
pub(crate) struct MetricsReportPayload {
    recorded_at: DateTime<Utc>,
    cpu_percent: f64,
    memory_used_bytes: i64,
    memory_total_bytes: i64,
    swap_used_bytes: i64,
    swap_total_bytes: i64,
    disk_used_bytes: i64,
    disk_total_bytes: i64,
    load_1: f64,
    load_5: f64,
    load_15: f64,
    network_receive_bps: f64,
    network_transmit_bps: f64,
    network_receive_bytes: i64,
    network_transmit_bytes: i64,
    process_count: i32,
    temperature_celsius: Option<f64>,
    uptime_seconds: i32,
    #[serde(default)]
    gpus: Vec<Value>,
    #[serde(default)]
    gpu_processes: Vec<Value>,
    #[serde(default)]
    top_consumers: Vec<Value>,
    #[serde(default)]
    disks: Vec<Value>,
}

async fn report_metrics(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<MetricsReportPayload>,
) -> Result<StatusCode, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO metric_samples (device_id, recorded_at, cpu_percent, memory_used_bytes, memory_total_bytes, \
         swap_used_bytes, swap_total_bytes, disk_used_bytes, disk_total_bytes, load_1, load_5, load_15, \
         network_receive_bps, network_transmit_bps, network_receive_bytes, network_transmit_bytes, \
         process_count, temperature_celsius, uptime_seconds) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
    )
    .bind(&device.id)
    .bind(payload.recorded_at)
    .bind(payload.cpu_percent)
    .bind(payload.memory_used_bytes)
    .bind(payload.memory_total_bytes)
    .bind(payload.swap_used_bytes)
    .bind(payload.swap_total_bytes)
    .bind(payload.disk_used_bytes)
    .bind(payload.disk_total_bytes)
    .bind(payload.load_1)
    .bind(payload.load_5)
    .bind(payload.load_15)
    .bind(payload.network_receive_bps)
    .bind(payload.network_transmit_bps)
    .bind(payload.network_receive_bytes)
    .bind(payload.network_transmit_bytes)
    .bind(payload.process_count)
    .bind(payload.temperature_celsius)
    .bind(payload.uptime_seconds)
    .execute(&mut *tx)
    .await?;

    for item in payload.top_consumers.iter().filter(|item| item.get("kind").and_then(Value::as_str) == Some("container")) {
        let Some(name) = item.get("name").and_then(Value::as_str).filter(|n| !n.is_empty()) else { continue };
        let cpu_percent = item.get("cpu_percent").and_then(Value::as_f64).unwrap_or(0.0);
        let memory_bytes = item.get("memory_bytes").and_then(Value::as_i64).unwrap_or(0);
        sqlx::query(
            "INSERT INTO container_metric_samples (device_id, recorded_at, container_name, cpu_percent, memory_bytes) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(&device.id)
        .bind(payload.recorded_at)
        .bind(truncate_chars(name, 255))
        .bind(cpu_percent)
        .bind(memory_bytes)
        .execute(&mut *tx)
        .await?;
    }

    let mut inventory = as_object(&device.inventory);
    inventory.insert("_monitoring".to_string(), json!({ "current": payload }));
    sqlx::query("UPDATE devices SET inventory = $1, last_seen = $2 WHERE id = $3")
        .bind(Value::Object(inventory))
        .bind(Utc::now())
        .bind(&device.id)
        .execute(&mut *tx)
        .await?;

    let retention_days = std::env::var("METRICS_RETENTION_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(7)
        .clamp(1, 90);
    let cutoff = Utc::now() - Duration::days(retention_days);
    sqlx::query("DELETE FROM metric_samples WHERE device_id = $1 AND recorded_at < $2")
        .bind(&device.id)
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM container_metric_samples WHERE device_id = $1 AND recorded_at < $2")
        .bind(&device.id)
        .bind(cutoff)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn heartbeat(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    sqlx::query("UPDATE devices SET last_seen = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(&device.id)
        .execute(&state.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_agent_settings(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    sqlx::query("UPDATE devices SET last_seen = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(&device.id)
        .execute(&state.db)
        .await?;
    let fleet = get_fleet_settings(&state).await?;
    let mut settings = as_object(&public_agent_settings(
        &device.inventory,
        fleet.default_metrics_interval_seconds,
        fleet.default_inventory_interval_seconds,
    ));
    settings.remove("uninstall_code_required");
    Ok(Json(Value::Object(settings)))
}

#[derive(Deserialize)]
struct UninstallVerifyPayload {
    #[serde(default)]
    code: String,
}

async fn verify_agent_uninstall(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<UninstallVerifyPayload>,
) -> Result<Json<Value>, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    let stored = device.inventory.get("_agent_settings").cloned().unwrap_or(json!({}));
    let encoded = stored.get("uninstall_code_hash").and_then(Value::as_str).unwrap_or("");
    if !encoded.is_empty() && !verify_password(&payload.code, encoded) {
        return Err(ApiError::forbidden("Invalid uninstall code"));
    }
    Ok(Json(json!({ "authorized": true })))
}

async fn next_job(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<axum::response::Response, ApiError> {
    let device = authenticate_from_headers(&state, &headers).await?;
    let mut tx = state.db.begin().await?;
    let device_row = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices WHERE id = $1 FOR UPDATE",
    )
    .bind(&device.id)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("UPDATE devices SET last_seen = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(&device.id)
        .execute(&mut *tx)
        .await?;
    queue_scheduled_scan(&mut tx, &device_row).await?;
    crate::deployment::queue_scheduled_patch(&mut tx, &device_row).await?;

    let job = sqlx::query_as::<_, JobRow>(
        "SELECT id, device_id, type, status, options, created_at, claimed_at, completed_at, exit_code, output, error \
         FROM jobs WHERE device_id = $1 AND status = 'pending' ORDER BY created_at ASC \
         FOR UPDATE SKIP LOCKED LIMIT 1",
    )
    .bind(&device.id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some(job) = job else {
        tx.commit().await?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    sqlx::query("UPDATE jobs SET status = 'running', claimed_at = $1 WHERE id = $2")
        .bind(Utc::now())
        .bind(&job.id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;

    let mut running = job;
    running.status = "running".to_string();
    Ok(Json(job_view(&running, false)).into_response())
}

#[derive(Deserialize)]
struct JobResultPayload {
    status: String,
    exit_code: Option<i32>,
    #[serde(default)]
    output: String,
    #[serde(default)]
    error: String,
}

async fn complete_job(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
    Json(payload): Json<JobResultPayload>,
) -> Result<StatusCode, ApiError> {
    if payload.status != "succeeded" && payload.status != "failed" {
        return Err(ApiError::bad_request("status must be succeeded or failed"));
    }
    let device = authenticate_from_headers(&state, &headers).await?;
    let row = sqlx::query("SELECT device_id, type, status FROM jobs WHERE id = $1")
        .bind(&job_id)
        .fetch_optional(&state.db)
        .await?;
    let Some(row) = row else {
        return Err(ApiError::not_found("Job not found"));
    };
    let job_device_id: String = row.get("device_id");
    if job_device_id != device.id {
        return Err(ApiError::not_found("Job not found"));
    }
    let status: String = row.get("status");
    // A job the lease-reaper already marked outcome_unknown (see
    // reap_stale_jobs) still accepts a late completion report: the agent
    // genuinely executed it and knows what happened, which is strictly
    // more useful than leaving the record as "unknown" forever. Only a
    // genuinely terminal status (succeeded/failed already recorded) is
    // rejected, to guard against a replayed or duplicate report.
    if status != "running" && status != "outcome_unknown" {
        return Err(ApiError::conflict("Job is not running"));
    }
    let job_type: String = row.get("type");
    let now = Utc::now();

    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE jobs SET status=$1, exit_code=$2, output=$3, error=$4, completed_at=$5 WHERE id=$6",
    )
    .bind(&payload.status)
    .bind(payload.exit_code)
    .bind(&payload.output)
    .bind(&payload.error)
    .bind(now)
    .bind(&job_id)
    .execute(&mut *tx)
    .await?;
    if matches!(job_type.as_str(), "INSTALL_UPDATES" | "INSTALL_APPROVED_UPDATES") && payload.status == "succeeded" {
        let mut inventory = as_object(&device.inventory);
        let mut patching = inventory
            .get("_patching")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        patching.insert("last_patched_at".to_string(), json!(now));
        patching.insert("job_id".to_string(), json!(job_id));
        inventory.insert("_patching".to_string(), Value::Object(patching));
        sqlx::query("UPDATE devices SET inventory = $1, last_seen = $2 WHERE id = $3")
            .bind(Value::Object(inventory))
            .bind(now)
            .bind(&device.id)
            .execute(&mut *tx)
            .await?;
    } else {
        sqlx::query("UPDATE devices SET last_seen = $1 WHERE id = $2")
            .bind(now)
            .bind(&device.id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    if payload.status == "failed" {
        let db = state.db.clone();
        let error = payload.error.clone();
        let job_type_owned = job_type.clone();
        let job_id_owned = job_id.clone();
        // Fire-and-forget: webhook delivery (possibly to a slow or
        // unreachable endpoint) must never add latency to the agent's own
        // job-completion request.
        tokio::spawn(async move {
            let error_ref = if error.is_empty() { None } else { Some(error.as_str()) };
            crate::alerting::notify_job_failed(&db, &device, &job_type_owned, &job_id_owned, error_ref).await;
        });
    }
    Ok(StatusCode::NO_CONTENT)
}

/// How long a job may sit "running" (claimed_at) before the sweep below
/// gives up waiting for a completion report and marks it outcome_unknown.
/// Generous relative to how long any job type here actually takes (the
/// slowest -- patch/software deployment, an arbitrary RUN_SCRIPT -- still
/// normally finishes in single-digit minutes); configurable in seconds
/// (rather than a coarser minutes/hours unit) both for a fleet with
/// unusually long-running custom scripts and so an integration test can
/// set a short lease without a multi-minute sleep.
fn job_lease_seconds() -> i64 {
    std::env::var("FLEETVIEW_JOB_LEASE_SECONDS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(1800)
}

fn job_reap_interval_seconds() -> u64 {
    std::env::var("FLEETVIEW_JOB_REAP_INTERVAL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(300)
}

const STALE_JOB_ERROR: &str =
    "Agent did not report a result within the lease window; its actual outcome is unknown.";

/// Recovers jobs an agent claimed and then never reported back on -- a
/// crash, a lost completion POST, or the device simply never coming back
/// online -- which would otherwise sit "running" forever. That's not just
/// a stale-looking row: devices.rs's own scheduled-scan/patch dedup checks
/// (e.g. queue_scheduled_scan) treat any pending-or-running job as "one's
/// already in flight" and skip queuing a new one, so a stuck job silently
/// blocks every future equivalent job too.
///
/// Deliberately does NOT retry or recreate the job -- the review comment
/// this exists for is explicit that auto-rerunning a job whose outcome is
/// unknown (it may have actually succeeded, or be a destructive command
/// still mid-flight) is itself risky. outcome_unknown is a terminal,
/// clearly-labeled dead end an admin decides what to do about, same as
/// they would a failed job -- complete_job still accepts a late report for
/// one of these (see its own comment) if the agent does eventually check
/// back in.
pub async fn reap_stale_jobs(pool: &PgPool) {
    let cutoff = Utc::now() - Duration::seconds(job_lease_seconds());
    let stale = sqlx::query(
        "UPDATE jobs SET status = 'outcome_unknown', completed_at = now(), error = $1 \
         WHERE status = 'running' AND claimed_at < $2 \
         RETURNING id, device_id, type",
    )
    .bind(STALE_JOB_ERROR)
    .bind(cutoff)
    .fetch_all(pool)
    .await;
    let Ok(stale) = stale else { return };
    for row in stale {
        let job_id: String = row.get("id");
        let device_id: String = row.get("device_id");
        let job_type: String = row.get("type");
        tracing::warn!("job {job_id} ({job_type}) on device {device_id} timed out waiting for a completion report; marked outcome_unknown");
        let device = sqlx::query_as::<_, Device>(
            "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
             package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
             installed_packages, available_updates, update_count, security_update_count, last_scan_at \
             FROM devices WHERE id = $1",
        )
        .bind(&device_id)
        .fetch_optional(pool)
        .await;
        if let Ok(Some(device)) = device {
            crate::alerting::notify_job_failed(pool, &device, &job_type, &job_id, Some(STALE_JOB_ERROR)).await;
        }
    }
}

pub async fn reap_stale_jobs_loop(pool: PgPool) {
    loop {
        reap_stale_jobs(&pool).await;
        tokio::time::sleep(std::time::Duration::from_secs(job_reap_interval_seconds())).await;
    }
}

// -- admin-facing endpoints --

async fn list_devices(State(state): State<Arc<AppState>>, _viewer: Viewer) -> Result<Json<Vec<Value>>, ApiError> {
    let devices = sqlx::query_as::<_, Device>(
        "SELECT id, hostname, display_name, platform, os_name, os_version, architecture, \
         package_manager, agent_version, agent_token_hash, enrolled_at, last_seen, inventory, \
         installed_packages, available_updates, update_count, security_update_count, last_scan_at \
         FROM devices ORDER BY hostname ASC",
    )
    .fetch_all(&state.db)
    .await?;
    let fleet = get_fleet_settings(&state).await?;
    Ok(Json(devices.iter().map(|d| device_view(d, &fleet, &state.hub, false)).collect()))
}

async fn get_device(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Path(id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    let fleet = get_fleet_settings(&state).await?;
    Ok(Json(device_view(&device, &fleet, &state.hub, true)))
}

async fn delete_device(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    if fetch_device(&state, &id).await?.is_none() {
        return Err(ApiError::not_found("Device not found"));
    }
    let mut tx = state.db.begin().await?;
    sqlx::query("DELETE FROM jobs WHERE device_id = $1").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM vulnerability_schedules WHERE device_id = $1").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM compliance_snapshots WHERE device_id = $1").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM metric_samples WHERE device_id = $1").bind(&id).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM container_metric_samples WHERE device_id = $1").bind(&id).execute(&mut *tx).await?;
    sqlx::query("UPDATE enrollment_tokens SET used_by_device_id = NULL WHERE used_by_device_id = $1")
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(&id).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct AgentSettingsUpdatePayload {
    metrics_interval_seconds: i32,
    inventory_interval_seconds: i32,
    #[serde(default = "default_true")]
    gpu_monitoring_enabled: bool,
    #[serde(default = "default_true")]
    docker_inventory_enabled: bool,
    #[serde(default)]
    uninstall_code_required: bool,
    uninstall_code: Option<String>,
}

fn default_true() -> bool {
    true
}

async fn update_device_settings(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Path(id): Path<String>,
    Json(payload): Json<AgentSettingsUpdatePayload>,
) -> Result<Json<Value>, ApiError> {
    if !(15..=3600).contains(&payload.metrics_interval_seconds)
        || !(300..=86400).contains(&payload.inventory_interval_seconds)
    {
        return Err(ApiError::bad_request("Interval out of range"));
    }
    if let Some(code) = &payload.uninstall_code {
        if code.len() < 4 || code.len() > 128 {
            return Err(ApiError::bad_request("Uninstall code must be 4-128 characters"));
        }
    }
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    let existing = device.inventory.get("_agent_settings").cloned().unwrap_or(json!({}));
    let existing_hash = existing.get("uninstall_code_hash").and_then(Value::as_str).unwrap_or("");
    if payload.uninstall_code_required && payload.uninstall_code.is_none() && existing_hash.is_empty() {
        return Err(ApiError::bad_request("Enter an uninstall code before enabling protection"));
    }
    let mut settings = json!({
        "metrics_interval_seconds": payload.metrics_interval_seconds,
        "inventory_interval_seconds": payload.inventory_interval_seconds,
        "gpu_monitoring_enabled": payload.gpu_monitoring_enabled,
        "docker_inventory_enabled": payload.docker_inventory_enabled,
    });
    if payload.uninstall_code_required {
        let hash = match &payload.uninstall_code {
            Some(code) => crate::security::password_hash(code),
            None => existing_hash.to_string(),
        };
        settings.as_object_mut().unwrap().insert("uninstall_code_hash".to_string(), json!(hash));
    }
    let mut inventory = as_object(&device.inventory);
    inventory.insert("_agent_settings".to_string(), settings);
    sqlx::query("UPDATE devices SET inventory = $1 WHERE id = $2")
        .bind(Value::Object(inventory.clone()))
        .bind(&id)
        .execute(&state.db)
        .await?;
    let fleet = get_fleet_settings(&state).await?;
    Ok(Json(public_agent_settings(
        &Value::Object(inventory),
        fleet.default_metrics_interval_seconds,
        fleet.default_inventory_interval_seconds,
    )))
}

const MAX_TAGS_PER_DEVICE: usize = 32;
const MAX_TAG_LENGTH: usize = 64;

#[derive(Deserialize)]
struct TagsUpdatePayload {
    tags: Vec<String>,
}

/// Tags live in inventory._tags (free-form strings), the same
/// stash-it-in-the-JSONB-column convention _agent_settings/_patching/
/// _monitoring already use elsewhere in this file -- grouping/bulk-
/// targeting devices is lightweight metadata, not something that needs
/// its own table with foreign keys and a migration.
async fn update_device_tags(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<TagsUpdatePayload>,
) -> Result<Json<Value>, ApiError> {
    if payload.tags.len() > MAX_TAGS_PER_DEVICE {
        return Err(ApiError::bad_request(format!("A device can have at most {MAX_TAGS_PER_DEVICE} tags")));
    }
    let mut tags: Vec<String> = Vec::new();
    for raw in &payload.tags {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > MAX_TAG_LENGTH {
            return Err(ApiError::bad_request(format!("Tags must be {MAX_TAG_LENGTH} characters or fewer")));
        }
        let normalized = trimmed.to_string();
        if !tags.iter().any(|existing| existing.eq_ignore_ascii_case(&normalized)) {
            tags.push(normalized);
        }
    }
    tags.sort_by_key(|tag| tag.to_lowercase());
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    let mut inventory = as_object(&device.inventory);
    inventory.insert("_tags".to_string(), json!(tags));
    sqlx::query("UPDATE devices SET inventory = $1 WHERE id = $2")
        .bind(Value::Object(inventory))
        .bind(&id)
        .execute(&state.db)
        .await?;
    Ok(Json(json!({ "tags": tags })))
}

#[derive(Deserialize)]
struct MetricsQuery {
    #[serde(default = "default_hours")]
    hours: i64,
}

fn default_hours() -> i64 {
    24
}

async fn get_device_metrics(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Path(id): Path<String>,
    Query(query): Query<MetricsQuery>,
) -> Result<Json<Vec<crate::models::MetricSample>>, ApiError> {
    let hours = query.hours.clamp(1, 168);
    if fetch_device(&state, &id).await?.is_none() {
        return Err(ApiError::not_found("Device not found"));
    }
    let cutoff = Utc::now() - Duration::hours(hours);
    let mut samples = sqlx::query_as::<_, crate::models::MetricSample>(
        "SELECT id, device_id, recorded_at, cpu_percent, memory_used_bytes, memory_total_bytes, \
         swap_used_bytes, swap_total_bytes, disk_used_bytes, disk_total_bytes, load_1, load_5, load_15, \
         network_receive_bps, network_transmit_bps, network_receive_bytes, network_transmit_bytes, \
         process_count, temperature_celsius, uptime_seconds \
         FROM metric_samples WHERE device_id = $1 AND recorded_at >= $2 \
         ORDER BY recorded_at DESC LIMIT 10080",
    )
    .bind(&id)
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;
    samples.reverse();
    Ok(Json(samples))
}

async fn get_device_container_metrics(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Path(id): Path<String>,
    Query(query): Query<MetricsQuery>,
) -> Result<Json<Vec<crate::models::ContainerMetricSample>>, ApiError> {
    let hours = query.hours.clamp(1, 168);
    if fetch_device(&state, &id).await?.is_none() {
        return Err(ApiError::not_found("Device not found"));
    }
    let cutoff = Utc::now() - Duration::hours(hours);
    // 120,960 = TopConsumersLimit (12 containers/sample) * get_device_metrics's
    // own 10,080 (one sample/minute for a full week) cap -- this table can
    // have up to that many container rows per device per week.
    let mut samples = sqlx::query_as::<_, crate::models::ContainerMetricSample>(
        "SELECT id, device_id, recorded_at, container_name, cpu_percent, memory_bytes \
         FROM container_metric_samples WHERE device_id = $1 AND recorded_at >= $2 \
         ORDER BY recorded_at DESC LIMIT 120960",
    )
    .bind(&id)
    .bind(cutoff)
    .fetch_all(&state.db)
    .await?;
    samples.reverse();
    Ok(Json(samples))
}

#[derive(Serialize)]
struct ScanScheduleView {
    interval_hours: i32,
    next_run_at: Option<DateTime<Utc>>,
    supported: bool,
}

async fn scan_schedule_view(state: &AppState, id: &str) -> Result<ScanScheduleView, ApiError> {
    let Some(device) = fetch_device(state, id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    let row = sqlx::query("SELECT interval_hours, next_run_at FROM vulnerability_schedules WHERE device_id = $1")
        .bind(id)
        .fetch_optional(&state.db)
        .await?;
    let (interval_hours, next_run_at) = match row {
        Some(row) => {
            let hours: i32 = row.get("interval_hours");
            let next: DateTime<Utc> = row.get("next_run_at");
            (hours, if hours != 0 { Some(next) } else { None })
        }
        None => (0, None),
    };
    Ok(ScanScheduleView {
        interval_hours,
        next_run_at,
        supported: scan_supported(&device),
    })
}

async fn get_scan_schedule(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
    Path(id): Path<String>,
) -> Result<Json<ScanScheduleView>, ApiError> {
    Ok(Json(scan_schedule_view(&state, &id).await?))
}

#[derive(Deserialize)]
struct ScheduleUpdatePayload {
    #[serde(default)]
    interval_hours: i32,
}

async fn set_scan_schedule(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(id): Path<String>,
    Json(payload): Json<ScheduleUpdatePayload>,
) -> Result<Json<ScanScheduleView>, ApiError> {
    if !(0..=8760).contains(&payload.interval_hours) {
        return Err(ApiError::bad_request("interval_hours must be between 0 and 8760"));
    }
    let Some(device) = fetch_device(&state, &id).await? else {
        return Err(ApiError::not_found("Device not found"));
    };
    if payload.interval_hours != 0 && !scan_supported(&device) {
        return Err(ApiError::bad_request(
            "Automatic vulnerability scans support Arch/CachyOS and Debian only",
        ));
    }
    sqlx::query(
        "INSERT INTO vulnerability_schedules (device_id, interval_hours, next_run_at) VALUES ($1, $2, $3) \
         ON CONFLICT (device_id) DO UPDATE SET interval_hours = $2, next_run_at = $3",
    )
    .bind(&id)
    .bind(payload.interval_hours)
    .bind(Utc::now() + Duration::hours(payload.interval_hours as i64))
    .execute(&state.db)
    .await?;
    Ok(Json(scan_schedule_view(&state, &id).await?))
}

#[derive(Serialize)]
struct FleetSettingsView {
    default_metrics_interval_seconds: i32,
    default_inventory_interval_seconds: i32,
}

async fn get_fleet_settings_endpoint(
    State(state): State<Arc<AppState>>,
    _viewer: Viewer,
) -> Result<Json<FleetSettingsView>, ApiError> {
    let fleet = get_fleet_settings(&state).await?;
    Ok(Json(FleetSettingsView {
        default_metrics_interval_seconds: fleet.default_metrics_interval_seconds,
        default_inventory_interval_seconds: fleet.default_inventory_interval_seconds,
    }))
}

#[derive(Deserialize)]
struct FleetSettingsUpdatePayload {
    #[serde(default = "default_metrics_interval")]
    default_metrics_interval_seconds: i32,
    #[serde(default = "default_inventory_interval")]
    default_inventory_interval_seconds: i32,
}

fn default_metrics_interval() -> i32 {
    60
}
fn default_inventory_interval() -> i32 {
    900
}

async fn update_fleet_settings(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Json(payload): Json<FleetSettingsUpdatePayload>,
) -> Result<Json<FleetSettingsView>, ApiError> {
    if !(15..=3600).contains(&payload.default_metrics_interval_seconds)
        || !(300..=86400).contains(&payload.default_inventory_interval_seconds)
    {
        return Err(ApiError::bad_request("Interval out of range"));
    }
    sqlx::query(
        "INSERT INTO fleet_settings (id, default_metrics_interval_seconds, default_inventory_interval_seconds, updated_at) \
         VALUES (1, $1, $2, now()) \
         ON CONFLICT (id) DO UPDATE SET default_metrics_interval_seconds = $1, default_inventory_interval_seconds = $2, updated_at = now()",
    )
    .bind(payload.default_metrics_interval_seconds)
    .bind(payload.default_inventory_interval_seconds)
    .execute(&state.db)
    .await?;
    Ok(Json(FleetSettingsView {
        default_metrics_interval_seconds: payload.default_metrics_interval_seconds,
        default_inventory_interval_seconds: payload.default_inventory_interval_seconds,
    }))
}

#[derive(Deserialize)]
struct ListJobsQuery {
    device_id: Option<String>,
}

async fn list_jobs(
    State(state): State<Arc<AppState>>,
    viewer: Viewer,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<Vec<Value>>, ApiError> {
    let redact = matches!(viewer.user(), Some(u) if u.role == "viewer");
    let jobs = if let Some(device_id) = &query.device_id {
        sqlx::query_as::<_, JobRow>(
            "SELECT id, device_id, type, status, options, created_at, claimed_at, completed_at, exit_code, output, error \
             FROM jobs WHERE device_id = $1 ORDER BY created_at DESC LIMIT 100",
        )
        .bind(device_id)
        .fetch_all(&state.db)
        .await?
    } else {
        sqlx::query_as::<_, JobRow>(
            "SELECT id, device_id, type, status, options, created_at, claimed_at, completed_at, exit_code, output, error \
             FROM jobs ORDER BY created_at DESC LIMIT 100",
        )
        .fetch_all(&state.db)
        .await?
    };
    Ok(Json(jobs.iter().map(|j| job_view(j, redact)).collect()))
}

const ALLOWED_JOB_TYPES: &[&str] = &[
    "SCAN_DEVICE",
    "SCAN_VULNERABILITIES",
    "INSTALL_UPDATES",
    "INSTALL_PACKAGE",
    "UNINSTALL_PACKAGE",
    "DOCKER_CONTAINER_ACTION",
    "DOCKER_COMPOSE_UP",
    "DOCKER_VOLUME_REMOVE",
    "DOCKER_VOLUME_PRUNE",
];

// Mirrors deployment.rs/live.rs's own private copy of this same check --
// each module that version-gates a job/feature keeps its own, rather than
// sharing one, matching how this codebase already does it.
fn version_at_least(version: Option<&str>, required: (i32, i32)) -> bool {
    let parts: Vec<i32> = version
        .unwrap_or("")
        .split('.')
        .take(2)
        .map(|p| p.parse::<i32>().unwrap_or(-1))
        .collect();
    matches!(parts.as_slice(), [major, minor] if (*major, *minor) >= required)
}

fn supports_docker_compose_up(device: &Device) -> bool {
    version_at_least(device.agent_version.as_deref(), (0, 29))
}

// docker compose's own project-name rule: lowercase alphanumerics, '-' and
// '_', starting with an alphanumeric. Enforced here too (not just agent-
// side) since this ends up as a shell argument and part of a temp file's
// container-grouping label on the endpoint.
const MAX_COMPOSE_BYTES: usize = 256 * 1024;

fn valid_compose_project(name: &str) -> bool {
    if name.is_empty() || name.len() > 63 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    if !first.is_ascii_lowercase() && !first.is_ascii_digit() {
        return false;
    }
    name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[derive(Deserialize)]
struct JobCreatePayload {
    #[serde(rename = "type")]
    job_type: String,
    #[serde(default)]
    options: Map<String, Value>,
}

fn valid_package_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 255 {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else { return false };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || ".-_+:".contains(c))
}

async fn create_job(
    State(state): State<Arc<AppState>>,
    _operator: Operator,
    Path(device_id): Path<String>,
    Json(payload): Json<JobCreatePayload>,
) -> Result<impl IntoResponse, ApiError> {
    if !ALLOWED_JOB_TYPES.contains(&payload.job_type.as_str()) {
        return Err(ApiError::bad_request("Unsupported job type"));
    }
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
    let Some(device) = device else {
        return Err(ApiError::not_found("Device not found"));
    };

    if payload.job_type == "INSTALL_UPDATES" {
        return Err(ApiError::bad_request(
            "Use approved patch deployment after reviewing each pending patch",
        ));
    }
    if matches!(payload.job_type.as_str(), "INSTALL_PACKAGE" | "UNINSTALL_PACKAGE") {
        let name = payload.options.get("package").and_then(Value::as_str);
        if !name.map(valid_package_name).unwrap_or(false) {
            return Err(ApiError::bad_request("A single literal package name or ID is required"));
        }
    }
    if payload.job_type == "UNINSTALL_PACKAGE" && payload.options.get("confirmed") != Some(&Value::Bool(true)) {
        return Err(ApiError::bad_request("UNINSTALL_PACKAGE requires options.confirmed=true"));
    }
    if payload.job_type == "DOCKER_CONTAINER_ACTION" {
        let version_ok = device
            .agent_version
            .as_deref()
            .unwrap_or("")
            .split('.')
            .take(2)
            .map(|p| p.parse::<i32>().unwrap_or(-1))
            .collect::<Vec<_>>();
        let supported = matches!(version_ok.as_slice(), [major, minor] if (*major, *minor) >= (0, 15));
        if !supported {
            return Err(ApiError::bad_request(
                "Upgrade this device's native agent to 0.15.0 before managing Docker",
            ));
        }
        let action = payload.options.get("action").and_then(Value::as_str);
        let container_id = payload.options.get("container_id").and_then(Value::as_str);
        let confirmed = payload.options.get("confirmed") == Some(&Value::Bool(true));
        let id_ok = container_id
            .map(|id| id.len() >= 12 && id.len() <= 64 && id.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false);
        if !confirmed
            || !matches!(action, Some("start") | Some("stop") | Some("restart"))
            || !id_ok
            || payload.options.len() != 3
        {
            return Err(ApiError::bad_request("A confirmed Docker action and container ID are required"));
        }
        let known = device.inventory.get("docker_containers").and_then(Value::as_array);
        let docker_available = device.inventory.get("docker_available") == Some(&Value::Bool(true));
        let container_known = known
            .map(|list| {
                list.iter()
                    .any(|item| item.get("id").and_then(Value::as_str) == container_id)
            })
            .unwrap_or(false);
        if !docker_available || !container_known {
            return Err(ApiError::bad_request(
                "Container is not in this device's latest Docker inventory",
            ));
        }
    }
    if payload.job_type == "DOCKER_VOLUME_REMOVE" || payload.job_type == "DOCKER_VOLUME_PRUNE" {
        let version_ok = device
            .agent_version
            .as_deref()
            .unwrap_or("")
            .split('.')
            .take(2)
            .map(|p| p.parse::<i32>().unwrap_or(-1))
            .collect::<Vec<_>>();
        let supported = matches!(version_ok.as_slice(), [major, minor] if (*major, *minor) >= (0, 31));
        if !supported {
            return Err(ApiError::bad_request(
                "Upgrade this device's native agent to 0.31.0 before managing Docker volumes",
            ));
        }
        let docker_available = device.inventory.get("docker_available") == Some(&Value::Bool(true));
        if !docker_available {
            return Err(ApiError::bad_request("Docker is not available on this device"));
        }
        let confirmed = payload.options.get("confirmed") == Some(&Value::Bool(true));
        if payload.job_type == "DOCKER_VOLUME_REMOVE" {
            let name = payload.options.get("name").and_then(Value::as_str);
            if !confirmed || name.is_none() || payload.options.len() != 2 {
                return Err(ApiError::bad_request("A confirmed Docker volume name is required"));
            }
            let known = device.inventory.get("docker_volumes").and_then(Value::as_array);
            let volume_known = known
                .map(|list| {
                    list.iter().any(|item| {
                        item.get("name").and_then(Value::as_str) == name
                            && item.get("in_use") != Some(&Value::Bool(true))
                    })
                })
                .unwrap_or(false);
            if !volume_known {
                return Err(ApiError::bad_request(
                    "Volume is not an unused volume in this device's latest Docker inventory",
                ));
            }
        } else if !confirmed || payload.options.len() != 1 {
            return Err(ApiError::bad_request("DOCKER_VOLUME_PRUNE requires options.confirmed=true"));
        }
    }
    if payload.job_type == "DOCKER_COMPOSE_UP" {
        if !supports_docker_compose_up(&device) {
            return Err(ApiError::bad_request(
                "Upgrade this device's native agent to 0.29.0 before deploying from a compose file",
            ));
        }
        let docker_available = device.inventory.get("docker_available") == Some(&Value::Bool(true));
        if !docker_available {
            return Err(ApiError::bad_request("Docker is not available on this device"));
        }
        let compose = payload.options.get("compose").and_then(Value::as_str);
        let project = payload.options.get("project").and_then(Value::as_str);
        let compose_ok = compose.map(|c| !c.trim().is_empty() && c.len() <= MAX_COMPOSE_BYTES).unwrap_or(false);
        let project_ok = project.map(valid_compose_project).unwrap_or(false);
        if !compose_ok || !project_ok || payload.options.len() != 2 {
            return Err(ApiError::bad_request(
                "A compose file and a valid project name are required",
            ));
        }
    }

    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM jobs WHERE device_id = $1 AND type = $2 AND status IN ('pending','running')",
    )
    .bind(&device_id)
    .bind(&payload.job_type)
    .fetch_optional(&mut *tx)
    .await?;
    if existing.is_some() {
        return Err(ApiError::conflict("An equivalent job is already pending or running"));
    }

    let job_id = Uuid::new_v4().to_string();
    crate::models::insert_job(&mut *tx, &job_id, &device_id, &payload.job_type, Value::Object(payload.options)).await?;
    let job = sqlx::query_as::<_, JobRow>(
        "SELECT id, device_id, type, status, options, created_at, claimed_at, completed_at, exit_code, output, error \
         FROM jobs WHERE id = $1",
    )
    .bind(&job_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok((StatusCode::CREATED, Json(job_view(&job, false))))
}
