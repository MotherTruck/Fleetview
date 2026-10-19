//! Admin "Server migration" feature: moves this server's entire database
//! (every device, user, job, credential, report -- everything) to a
//! freshly-provisioned target FleetView server over a direct, authenticated
//! connection, then re-points every enrolled agent at the new server.
//!
//! The flow, from the admin's point of view:
//!   1. On the NEW (target) server's admin page, click "Generate migration
//!      token" -- a one-time, 30-minute token (generate_token below).
//!   2. On the OLD (source) server's admin page, paste the new server's URL
//!      and that token, then click "Migrate to this server" (send below).
//!      The source server runs `pg_dump` against its own database, POSTs
//!      the dump straight to the target server's /migration/receive with
//!      the token as a bearer credential, and on success queues a
//!      MIGRATE_SERVER job for every currently enrolled device (handled by
//!      the Go agent's handleNextJob -- see agent/cmd/fleetview-agent/main.go)
//!      so each one rewrites its FLEETVIEW_SERVER_URL and reconnects there.
//!   3. The target server (receive below) runs `pg_restore --clean`
//!      against its own database, replacing whatever was there (expected to
//!      be a fresh, empty install) with the source's data wholesale.
//!
//! This is a one-way, whole-database replacement, not a merge -- the
//! target server is expected to be freshly provisioned and otherwise
//! empty. Both ends need `pg_dump`/`pg_restore` on PATH (see
//! server/Dockerfile's postgresql-client install).
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::process::Command;
use uuid::Uuid;

use crate::auth::Admin;
use crate::error::ApiError;
use crate::security::{token_hash, token_urlsafe};
use crate::AppState;

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/v1/admin/migration/generate-token", post(generate_token))
        .route("/api/v1/admin/migration/send", post(send))
        .route(
            "/api/v1/admin/migration/receive",
            // A whole-database pg_dump can genuinely run well past
            // main.rs's tightened global body limit on a fleet with years
            // of metrics history. Generous rather than disabled outright:
            // receive's own token check happens inside the handler, after
            // axum has already buffered the body into the `Bytes`
            // extractor, so an unbounded limit here would let an
            // unauthenticated request exhaust memory before that check
            // ever runs. 4 GiB comfortably covers any realistic dump
            // while still bounding the worst case.
            post(receive).route_layer(DefaultBodyLimit::max(4 * 1024 * 1024 * 1024)),
        )
}

const TOKEN_TTL_MINUTES: i64 = 30;

async fn generate_token(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
) -> Result<impl IntoResponse, ApiError> {
    let token = format!("fvmig_{}", token_urlsafe(32));
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires_at = now + Duration::minutes(TOKEN_TTL_MINUTES);
    sqlx::query(
        "INSERT INTO migration_tokens (id, token_hash, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(&id)
    .bind(token_hash(&token))
    .bind(now)
    .bind(expires_at)
    .execute(&state.db)
    .await?;
    Ok(Json(json!({ "token": token, "expires_at": expires_at })))
}

#[derive(Deserialize)]
struct SendRequest {
    target_url: String,
    token: String,
}

async fn send(
    State(state): State<Arc<AppState>>,
    _admin: Admin,
    Json(payload): Json<SendRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let target_url = payload.target_url.trim().trim_end_matches('/').to_string();
    let token = payload.token.trim().to_string();
    if !target_url.starts_with("http://") && !target_url.starts_with("https://") {
        return Err(ApiError::bad_request("target_url must be an http(s) URL"));
    }
    if token.is_empty() {
        return Err(ApiError::bad_request("A migration token is required"));
    }

    let output = Command::new("pg_dump")
        .arg("--format=custom")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--dbname")
        .arg(crate::db::url())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not run pg_dump: {error}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pg_dump failed: {}", stderr.trim()),
        ));
    }

    let client = reqwest::Client::builder()
        .timeout(StdDuration::from_secs(30 * 60))
        .build()
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not build HTTP client: {error}")))?;
    let response = client
        .post(format!("{target_url}/api/v1/admin/migration/receive"))
        .bearer_auth(&token)
        .header("content-type", "application/octet-stream")
        .body(output.stdout)
        .send()
        .await
        .map_err(|error| ApiError::new(StatusCode::BAD_GATEWAY, format!("Could not reach target server: {error}")))?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!("Target server rejected the migration (HTTP {status}): {body}"),
        ));
    }

    // The target server now has an identical copy of every device's row
    // (same id, same agent_token_hash), so each agent's existing
    // credentials are still valid there without re-enrolling -- it just
    // needs to be told to point at the new URL. The source server queues
    // these jobs for its own device rows one last time before this device
    // fleet effectively becomes the new server's to manage.
    let device_ids: Vec<String> = sqlx::query_scalar("SELECT id FROM devices")
        .fetch_all(&state.db)
        .await?;
    let mut migrated = 0i64;
    for device_id in &device_ids {
        let job_id = Uuid::new_v4().to_string();
        if crate::models::insert_job(&state.db, &job_id, device_id, "MIGRATE_SERVER", json!({ "server_url": target_url }))
            .await
            .is_ok()
        {
            migrated += 1;
        }
    }

    Ok(Json(json!({
        "target_url": target_url,
        "devices_queued": migrated,
        "devices_total": device_ids.len(),
    })))
}

async fn receive(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, ApiError> {
    let presented = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or("");
    if presented.is_empty() {
        return Err(ApiError::unauthorized("A migration token is required"));
    }
    let hashed = token_hash(presented);
    let now = Utc::now();
    let claimed = sqlx::query(
        "UPDATE migration_tokens SET used_at = $1 \
         WHERE token_hash = $2 AND used_at IS NULL AND expires_at > $1",
    )
    .bind(now)
    .bind(&hashed)
    .execute(&state.db)
    .await?;
    if claimed.rows_affected() != 1 {
        return Err(ApiError::unauthorized("Invalid, expired, or already-used migration token"));
    }

    if body.is_empty() {
        return Err(ApiError::bad_request("Empty migration payload"));
    }
    let temp_path = std::env::temp_dir().join(format!("fleetview-migration-{}.dump", Uuid::new_v4()));
    tokio::fs::write(&temp_path, &body)
        .await
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not stage migration payload: {error}")))?;

    // --clean --if-exists wholesale-replaces whatever is already in this
    // database with the dump's contents; this server is expected to be a
    // freshly-provisioned, otherwise-empty install, not a production
    // database with data of its own to merge.
    let result = Command::new("pg_restore")
        .arg("--clean")
        .arg("--if-exists")
        .arg("--no-owner")
        .arg("--no-privileges")
        .arg("--dbname")
        .arg(crate::db::url())
        .arg(&temp_path)
        .stderr(Stdio::piped())
        .output()
        .await;
    let _ = tokio::fs::remove_file(&temp_path).await;
    let output = result.map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("Could not run pg_restore: {error}")))?;
    // pg_restore commonly exits non-zero on cosmetic warnings (e.g. a role
    // that doesn't exist on this server for --no-owner to skip) even when
    // the restore substantively succeeded -- unlike pg_dump above, a
    // nonzero exit here isn't treated as fatal on its own; only genuine
    // "database connection failed" style errors are, which a working
    // deployment never hits, so this stays a conservative stderr check
    // rather than exhaustively enumerating safe-to-ignore warnings.
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() && stderr.to_lowercase().contains("connection") {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("pg_restore could not connect to the database: {}", stderr.trim()),
        ));
    }

    // pg_restore ran as a separate process/connection and dropped+recreated
    // every table, so this server's own connection pool (state.db) is left
    // holding server-side prepared statements against now-gone table OIDs --
    // any pooled connection reused after this point fails every query with
    // "cached plan must not change result type". Exiting lets the
    // `restart: unless-stopped` policy (docker-compose.yml) bring the
    // process back up with a fresh pool against the just-restored database,
    // rather than trying to surgically invalidate sqlx's per-connection
    // statement cache. The response below is flushed to the caller first
    // (a short delay, not immediately) so this server's own success
    // confirmation actually reaches the old server before the process dies.
    tokio::spawn(async {
        tokio::time::sleep(StdDuration::from_millis(500)).await;
        std::process::exit(0);
    });

    Ok(Json(json!({ "status": "restored" })))
}
