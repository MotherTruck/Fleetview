use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

/// Mirrors server/app/database.py's DATABASE_URL handling, Postgres-only:
/// production always runs Postgres (see docker-compose.yml); the Python
/// server's SQLite path exists solely for that test suite's convenience,
/// which the Rust port replaces with a real local Postgres instance
/// instead (see server-rs/README or the test setup) -- closer to
/// production, and sidesteps SQLite/Postgres behavioral differences.
pub async fn connect() -> anyhow::Result<PgPool> {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://fleetview:fleetview@localhost/fleetview_dev".to_string());
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&url)
        .await?;
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
}
