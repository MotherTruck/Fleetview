//! Mirrors server/app/models.py field-for-field. See migrations/0001_init.sql
//! for the DDL these map onto.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;

/// Every job-queuing call site used to omit `status`/`created_at`, relying
/// on 0001_init.sql's column defaults ('pending', now()) -- which matches a
/// fresh sqlx-migrated database, but not a production database whose schema
/// was actually created by the original Python/Alembic migrations (those
/// columns are NOT NULL there with no database-level default, so every
/// omitted insert failed outright). Centralized here, explicit about both
/// values, so no call site can silently regress to relying on a default
/// that may not exist.
pub async fn insert_job<'e, E>(
    executor: E,
    id: &str,
    device_id: &str,
    job_type: &str,
    options: Value,
) -> Result<(), sqlx::Error>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO jobs (id, device_id, type, status, options, created_at) \
         VALUES ($1, $2, $3, 'pending', $4, now())",
    )
    .bind(id)
    .bind(device_id)
    .bind(job_type)
    .bind(options)
    .execute(executor)
    .await?;
    Ok(())
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub role: String,
    pub active: bool,
    pub must_change_password: bool,
    pub created_at: DateTime<Utc>,
    pub last_login_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow)]
pub struct UserSession {
    pub token_hash: String,
    pub user_id: String,
    pub csrf_token: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct LoginThrottle {
    pub key: String,
    pub attempts: i32,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct AccountAudit {
    pub id: i32,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub details: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub hostname: String,
    pub display_name: Option<String>,
    pub platform: String,
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub architecture: Option<String>,
    pub package_manager: Option<String>,
    pub agent_version: Option<String>,
    #[serde(skip_serializing)]
    pub agent_token_hash: String,
    pub enrolled_at: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub inventory: Value,
    pub installed_packages: Value,
    pub available_updates: Value,
    pub update_count: i32,
    pub security_update_count: i32,
    pub last_scan_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Job {
    pub id: String,
    pub device_id: String,
    #[sqlx(rename = "type")]
    pub job_type: String,
    pub status: String,
    pub options: Value,
    pub created_at: DateTime<Utc>,
    pub claimed_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub output: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, FromRow)]
pub struct EnrollmentToken {
    pub id: String,
    pub token_hash: String,
    pub label: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
    pub used_by_device_id: Option<String>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct MetricSample {
    pub id: i32,
    pub device_id: String,
    pub recorded_at: DateTime<Utc>,
    pub cpu_percent: f64,
    pub memory_used_bytes: i64,
    pub memory_total_bytes: i64,
    pub swap_used_bytes: i64,
    pub swap_total_bytes: i64,
    pub disk_used_bytes: i64,
    pub disk_total_bytes: i64,
    pub load_1: f64,
    pub load_5: f64,
    pub load_15: f64,
    pub network_receive_bps: f64,
    pub network_transmit_bps: f64,
    pub network_receive_bytes: i64,
    pub network_transmit_bytes: i64,
    pub process_count: i32,
    pub temperature_celsius: Option<f64>,
    pub uptime_seconds: i32,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct ContainerMetricSample {
    pub id: i32,
    pub device_id: String,
    pub recorded_at: DateTime<Utc>,
    pub container_name: String,
    pub cpu_percent: f64,
    pub memory_bytes: i64,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct Package {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
    pub category: String,
    pub pacman_name: String,
    pub apt_name: String,
    pub winget_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct FleetSettings {
    pub id: i32,
    pub default_metrics_interval_seconds: i32,
    pub default_inventory_interval_seconds: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct VulnerabilitySchedule {
    pub device_id: String,
    pub interval_hours: i32,
    pub next_run_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PatchApproval {
    pub device_id: String,
    pub package_key: String,
    pub available_version: String,
    pub approved: bool,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct PatchSchedule {
    pub device_id: String,
    pub interval_hours: i32,
    pub next_run_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow, Serialize)]
pub struct CustomPackage {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub command: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct CustomPackageFile {
    pub id: String,
    pub package_id: String,
    pub filename: String,
    pub size: i32,
    pub sha256: String,
    pub content: Vec<u8>,
}

#[derive(Debug, Clone, FromRow)]
pub struct Integration {
    pub id: String,
    pub kind: String,
    pub name: String,
    pub base_url: String,
    pub verify_tls: bool,
    pub encrypted_credentials: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_synced_at: Option<DateTime<Utc>>,
    pub last_sync_error: Option<String>,
    pub cached_data: Value,
}

#[derive(Debug, Clone, FromRow)]
pub struct ComplianceSnapshot {
    pub id: i32,
    pub device_id: String,
    pub snapshot_date: String,
    pub recorded_at: DateTime<Utc>,
    pub update_count: i32,
    pub security_update_count: i32,
    pub vulnerability_count: i32,
    pub critical_vulnerability_count: i32,
    pub high_vulnerability_count: i32,
    pub online: bool,
}
