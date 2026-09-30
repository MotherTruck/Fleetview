mod accounts;
mod auth;
mod connectors;
mod db;
mod deployment;
mod devices;
mod enrollment;
mod error;
mod integrations;
mod live;
mod models;
mod reports;
mod secrets_crypto;
mod security;

use axum::{routing::get, Json, Router};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

pub struct AppState {
    pub db: PgPool,
    pub hub: live::LiveHub,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let pool = db::connect().await?;
    tokio::spawn(integrations::periodic_sync_loop(pool.clone()));
    let state = Arc::new(AppState { db: pool, hub: live::LiveHub::new() });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(accounts::router())
        .merge(enrollment::router())
        .merge(devices::router())
        .merge(deployment::router())
        .merge(live::router())
        .merge(reports::router())
        .merge(integrations::router())
        .with_state(state);

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("listening on {bind}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}
