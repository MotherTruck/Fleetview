//! Mirrors server/app/integrations.py: connections to external home-lab
//! services (Proxmox, OPNsense), whose inventory is pulled in and shown
//! alongside FleetView's own fleet. Credentials are encrypted at rest
//! (secrets_crypto.rs) and never returned by any endpoint here; every
//! response is built through `IntegrationView`, which only ever carries the
//! non-secret columns.
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post, put};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::PgPool;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

use crate::auth::{Admin, Viewer};
use crate::error::ApiError;
use crate::models::Integration;
use crate::AppState;

const SYNC_INTERVAL_SECONDS: u64 = 120;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/integrations", get(list_integrations).post(create_integration))
        .route("/api/v1/admin/integrations/:id", put(update_integration).delete(delete_integration))
        .route("/api/v1/admin/integrations/:id/sync", post(trigger_sync))
}

fn required_credential_fields(kind: &str) -> Option<&'static [&'static str]> {
    match kind {
        "proxmox" => Some(crate::connectors::proxmox::REQUIRED_CREDENTIAL_FIELDS),
        "opnsense" => Some(crate::connectors::opnsense::REQUIRED_CREDENTIAL_FIELDS),
        _ => None,
    }
}

#[derive(Deserialize)]
struct IntegrationInput {
    kind: String,
    name: String,
    base_url: String,
    #[serde(default = "default_true")]
    verify_tls: bool,
    #[serde(default)]
    credentials: HashMap<String, String>,
}

fn default_true() -> bool {
    true
}

impl IntegrationInput {
    fn validate_shape(&self) -> Result<(), ApiError> {
        if !matches!(self.kind.as_str(), "proxmox" | "opnsense") {
            return Err(ApiError::bad_request(format!("Unsupported integration kind {:?}", self.kind)));
        }
        if self.name.is_empty() || self.name.len() > 255 {
            return Err(ApiError::bad_request("name must be between 1 and 255 characters"));
        }
        if self.base_url.is_empty() || self.base_url.len() > 500 {
            return Err(ApiError::bad_request("base_url must be between 1 and 500 characters"));
        }
        Ok(())
    }
}

fn validate_credentials(kind: &str, credentials: &HashMap<String, String>, require_all: bool) -> Result<HashMap<String, String>, ApiError> {
    let fields = required_credential_fields(kind).expect("kind already validated");
    let cleaned: HashMap<String, String> = credentials
        .iter()
        .filter(|(key, value)| fields.contains(&key.as_str()) && !value.trim().is_empty())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    if require_all {
        let have: HashSet<&str> = cleaned.keys().map(String::as_str).collect();
        let need: HashSet<&str> = fields.iter().copied().collect();
        if have != need {
            return Err(ApiError::bad_request(format!("{kind} requires: {}", fields.join(", "))));
        }
    }
    Ok(cleaned)
}

fn encrypt_credentials(credentials: &HashMap<String, String>) -> Result<String, ApiError> {
    let json = serde_json::to_string(credentials).expect("HashMap<String,String> always serializes");
    crate::secrets_crypto::encrypt_text(&json).map_err(|error| ApiError::new(StatusCode::CONFLICT, error.to_string()))
}

#[derive(Serialize)]
struct IntegrationView {
    id: String,
    kind: String,
    name: String,
    base_url: String,
    verify_tls: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_synced_at: Option<DateTime<Utc>>,
    last_sync_error: Option<String>,
    cached_data: Value,
}

impl From<&Integration> for IntegrationView {
    fn from(i: &Integration) -> Self {
        IntegrationView {
            id: i.id.clone(),
            kind: i.kind.clone(),
            name: i.name.clone(),
            base_url: i.base_url.clone(),
            verify_tls: i.verify_tls,
            created_at: i.created_at,
            updated_at: i.updated_at,
            last_synced_at: i.last_synced_at,
            last_sync_error: i.last_sync_error.clone(),
            cached_data: i.cached_data.clone(),
        }
    }
}

async fn fetch_integration(db: &PgPool, id: &str) -> Result<Integration, ApiError> {
    sqlx::query_as::<_, Integration>(
        "SELECT id, kind, name, base_url, verify_tls, encrypted_credentials, created_at, updated_at, \
         last_synced_at, last_sync_error, cached_data FROM integrations WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await?
    .ok_or_else(|| ApiError::not_found("Integration not found"))
}

async fn audit(db: &PgPool, actor: &str, action: &str, target: &str, details: &str) -> Result<(), ApiError> {
    sqlx::query("INSERT INTO account_audit (actor, action, target, details, created_at) VALUES ($1, $2, $3, $4, now())")
        .bind(actor)
        .bind(action)
        .bind(target)
        .bind(details)
        .execute(db)
        .await?;
    Ok(())
}

fn actor_name(viewer: &Viewer) -> String {
    viewer.user().map(|u| u.username.clone()).unwrap_or_else(|| "bootstrap".to_string())
}

/// Fetches fresh data from the external service and updates the row in
/// place (both the in-memory struct and the DB row). Never returns an
/// error to the caller -- failures are recorded in last_sync_error so one
/// unreachable integration can't break the admin listing or the periodic
/// loop that calls this for every configured integration in turn.
async fn sync_integration(db: &PgPool, integration: &mut Integration) {
    let credentials = match required_credential_fields(&integration.kind) {
        None => {
            integration.last_sync_error = Some(format!("Unknown integration kind {:?}", integration.kind));
            None
        }
        Some(_) => match crate::secrets_crypto::decrypt_text(&integration.encrypted_credentials) {
            Err(error) => {
                integration.last_sync_error = Some(error.to_string());
                None
            }
            Ok(json) => match serde_json::from_str::<HashMap<String, String>>(&json) {
                Ok(creds) => Some(creds),
                Err(error) => {
                    integration.last_sync_error = Some(error.to_string());
                    None
                }
            },
        },
    };

    if let Some(credentials) = credentials {
        let result = match integration.kind.as_str() {
            "proxmox" => crate::connectors::proxmox::fetch_inventory(&integration.base_url, &credentials, integration.verify_tls).await,
            "opnsense" => crate::connectors::opnsense::fetch_inventory(&integration.base_url, &credentials, integration.verify_tls).await,
            _ => unreachable!("checked by required_credential_fields above"),
        };
        match result {
            Ok(data) => {
                integration.cached_data = data;
                integration.last_synced_at = Some(Utc::now());
                integration.last_sync_error = None;
            }
            Err(error) => {
                integration.last_sync_error = Some(error);
            }
        }
    }

    let now = Utc::now();
    integration.updated_at = now;
    let result = sqlx::query(
        "UPDATE integrations SET cached_data = $1, last_synced_at = $2, last_sync_error = $3, updated_at = $4 WHERE id = $5",
    )
    .bind(&integration.cached_data)
    .bind(integration.last_synced_at)
    .bind(&integration.last_sync_error)
    .bind(now)
    .bind(&integration.id)
    .execute(db)
    .await;
    if let Err(error) = result {
        tracing::error!("failed to persist integration sync result: {error}");
    }
}

async fn list_integrations(State(state): State<Arc<AppState>>, _viewer: Viewer) -> Result<Json<Vec<IntegrationView>>, ApiError> {
    let integrations = sqlx::query_as::<_, Integration>(
        "SELECT id, kind, name, base_url, verify_tls, encrypted_credentials, created_at, updated_at, \
         last_synced_at, last_sync_error, cached_data FROM integrations ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(integrations.iter().map(IntegrationView::from).collect()))
}

async fn create_integration(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Json(payload): Json<IntegrationInput>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    payload.validate_shape()?;
    let credentials = validate_credentials(&payload.kind, &payload.credentials, true)?;
    let encrypted = encrypt_credentials(&credentials)?;

    let id = Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO integrations (id, kind, name, base_url, verify_tls, encrypted_credentials, created_at, updated_at, cached_data) \
         VALUES ($1, $2, $3, $4, $5, $6, now(), now(), '{}')",
    )
    .bind(&id)
    .bind(&payload.kind)
    .bind(&payload.name)
    .bind(&payload.base_url)
    .bind(payload.verify_tls)
    .bind(&encrypted)
    .execute(&state.db)
    .await?;

    audit(&state.db, &actor_name(&admin.0), "integration_created", &payload.name, &payload.kind).await?;

    let mut integration = fetch_integration(&state.db, &id).await?;
    sync_integration(&state.db, &mut integration).await;
    Ok((StatusCode::CREATED, Json(IntegrationView::from(&integration))))
}

async fn update_integration(
    State(state): State<Arc<AppState>>,
    admin: Admin,
    Path(id): Path<String>,
    Json(payload): Json<IntegrationInput>,
) -> Result<Json<IntegrationView>, ApiError> {
    let existing = fetch_integration(&state.db, &id).await?;
    payload.validate_shape()?;
    let credentials = validate_credentials(&payload.kind, &payload.credentials, false)?;

    let encrypted_credentials = if !credentials.is_empty() {
        encrypt_credentials(&credentials)?
    } else if existing.kind != payload.kind {
        return Err(ApiError::bad_request("Changing the integration kind requires re-entering credentials"));
    } else {
        existing.encrypted_credentials.clone()
    };

    sqlx::query(
        "UPDATE integrations SET kind = $1, name = $2, base_url = $3, verify_tls = $4, \
         encrypted_credentials = $5, updated_at = $6 WHERE id = $7",
    )
    .bind(&payload.kind)
    .bind(&payload.name)
    .bind(&payload.base_url)
    .bind(payload.verify_tls)
    .bind(&encrypted_credentials)
    .bind(Utc::now())
    .bind(&id)
    .execute(&state.db)
    .await?;

    audit(&state.db, &actor_name(&admin.0), "integration_updated", &payload.name, &payload.kind).await?;

    let mut integration = fetch_integration(&state.db, &id).await?;
    sync_integration(&state.db, &mut integration).await;
    Ok(Json(IntegrationView::from(&integration)))
}

async fn delete_integration(State(state): State<Arc<AppState>>, admin: Admin, Path(id): Path<String>) -> Result<StatusCode, ApiError> {
    let existing = fetch_integration(&state.db, &id).await?;
    audit(&state.db, &actor_name(&admin.0), "integration_deleted", &existing.name, &existing.kind).await?;
    sqlx::query("DELETE FROM integrations WHERE id = $1").bind(&id).execute(&state.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn trigger_sync(State(state): State<Arc<AppState>>, _admin: Admin, Path(id): Path<String>) -> Result<Json<IntegrationView>, ApiError> {
    let mut integration = fetch_integration(&state.db, &id).await?;
    sync_integration(&state.db, &mut integration).await;
    Ok(Json(IntegrationView::from(&integration)))
}

/// Started from main.rs; keeps every configured integration's cached_data
/// fresh without requiring an admin to click refresh.
pub async fn periodic_sync_loop(db: PgPool) {
    loop {
        let integrations = sqlx::query_as::<_, Integration>(
            "SELECT id, kind, name, base_url, verify_tls, encrypted_credentials, created_at, updated_at, \
             last_synced_at, last_sync_error, cached_data FROM integrations",
        )
        .fetch_all(&db)
        .await;
        match integrations {
            Ok(rows) => {
                for mut integration in rows {
                    sync_integration(&db, &mut integration).await;
                }
            }
            Err(error) => tracing::error!("integration sync loop iteration failed: {error}"),
        }
        tokio::time::sleep(Duration::from_secs(SYNC_INTERVAL_SECONDS)).await;
    }
}
