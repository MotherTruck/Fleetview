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

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Json, Router};
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use tower_http::services::{ServeDir, ServeFile};

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

    let static_dir = std::env::var("FLEETVIEW_STATIC_DIR").unwrap_or_else(|_| "static".to_string());
    let index_path = std::path::Path::new(&static_dir).join("index.html");

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(accounts::router())
        .merge(enrollment::router())
        .merge(devices::router())
        .merge(deployment::router())
        .merge(live::router())
        .merge(reports::router())
        .merge(integrations::router())
        .with_state(state)
        .route_service("/", ServeFile::new(index_path))
        .nest_service("/static", ServeDir::new(&static_dir))
        .layer(middleware::from_fn(security_headers));

    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    // Logs the OS-resolved address (not just the requested `bind` string) so
    // that passing port 0 to get a free port -- as the integration test
    // harness does -- has a discoverable result.
    println!("listening on {}", listener.local_addr()?);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// Mirrors server/app/main.py's `private_responses` middleware exactly: a
/// baseline set of defensive headers on every response, plus Cache-Control:
/// no-store on API responses specifically (session cookies, CSRF tokens,
/// and device/job data must never be cached by a shared proxy or the
/// browser's back/forward cache).
async fn security_headers(request: Request, next: Next) -> Response {
    let is_api = request.uri().path().starts_with("/api/");
    let mut response = next.run(request).await.into_response();
    let headers = response.headers_mut();
    headers.insert("X-Content-Type-Options", HeaderValue::from_static("nosniff"));
    headers.insert("X-Frame-Options", HeaderValue::from_static("DENY"));
    headers.insert("Referrer-Policy", HeaderValue::from_static("same-origin"));
    if is_api {
        headers.insert("Cache-Control", HeaderValue::from_static("no-store"));
    }
    response
}
