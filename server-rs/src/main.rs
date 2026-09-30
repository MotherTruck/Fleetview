mod accounts;
mod auth;
mod db;
mod enrollment;
mod error;
mod models;
mod security;

use axum::{routing::get, Json, Router};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: PgPool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let pool = db::connect().await?;
    let state = Arc::new(AppState { db: pool });

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(accounts::router())
        .merge(enrollment::router())
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
