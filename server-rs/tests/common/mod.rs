//! Shared harness for black-box HTTP integration tests: spawns the real
//! compiled server binary against a real, freshly-created Postgres
//! database (never SQLite -- see server/app's own live.py docstring on why
//! the Python test suite's SQLite shortcut doesn't apply here) and drives
//! it over HTTP exactly like the Python suite's FastAPI TestClient did.
#![allow(dead_code)]
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use uuid::Uuid;

pub const ADMIN_TOKEN: &str = "test-admin-token";
pub const PASSWORD: &str = "a-long-test-password-123";

pub struct TestServer {
    pub base_url: String,
    pub database_url: String,
    db_name: String,
    child: Child,
}

impl TestServer {
    pub async fn start() -> Self {
        Self::start_with_env(&[]).await
    }

    pub async fn start_with_env(extra_env: &[(&str, String)]) -> Self {
        let db_name = format!("fleetview_test_{}", Uuid::new_v4().simple());
        create_test_db(&db_name);

        let bin = env!("CARGO_BIN_EXE_fleetview-server");
        let database_url = format!("postgres://fleetview:fleetview@localhost/{db_name}");

        let mut cmd = Command::new(bin);
        cmd.env("DATABASE_URL", &database_url)
            .env("BIND_ADDR", "127.0.0.1:0")
            .env("ADMIN_TOKEN", ADMIN_TOKEN)
            .env("FLEETVIEW_SECRET_KEY", generate_fernet_key())
            .env_remove("RUST_LOG")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in extra_env {
            // A blank value means "unset this var" -- used by tests that need
            // FLEETVIEW_SECRET_KEY genuinely absent, not just empty, since
            // the default above always sets one.
            if value.is_empty() {
                cmd.env_remove(key);
            } else {
                cmd.env(key, value);
            }
        }
        let mut child = cmd.spawn().expect("spawn fleetview-server binary");

        let stdout = child.stdout.take().expect("captured stdout");
        let mut reader = BufReader::new(stdout);
        let mut port = None;
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line).expect("read server stdout");
            if bytes == 0 {
                break;
            }
            if let Some(addr) = line.trim().strip_prefix("listening on ") {
                port = addr.rsplit(':').next().map(str::to_string);
                break;
            }
        }
        // Keep draining stdout/stderr in the background so the child never
        // blocks on a full pipe buffer.
        std::thread::spawn(move || for _ in reader.lines() {});
        if let Some(stderr) = child.stderr.take() {
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for _ in reader.lines() {}
            });
        }

        let port = port.expect("server never printed its listening address");
        let base_url = format!("http://127.0.0.1:{port}");

        let probe = reqwest::Client::new();
        let mut ready = false;
        for _ in 0..200 {
            if probe.get(format!("{base_url}/healthz")).send().await.is_ok() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(ready, "server did not become healthy in time");

        TestServer { base_url, database_url, db_name, child }
    }

    /// A fresh HTTP client with its own cookie jar, standing in for a new
    /// browser session (Python's `TestClient(app)`).
    pub fn client(&self) -> reqwest::Client {
        reqwest::Client::builder().cookie_store(true).build().expect("build reqwest client")
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// Inserts a device row directly (bypassing HTTP enrollment), the same
    /// way Python's tests build fixtures by touching the SQLAlchemy session
    /// directly in setUp rather than going through the enroll endpoint.
    pub async fn seed_device(&self, id: &str, hostname: &str, agent_token_hash: &str) {
        let pool = sqlx::PgPool::connect(&self.database_url).await.expect("connect to test db");
        sqlx::query(
            "INSERT INTO devices (id, hostname, os_name, package_manager, agent_token_hash) \
             VALUES ($1, $2, 'Debian', 'apt', $3)",
        )
        .bind(id)
        .bind(hostname)
        .bind(agent_token_hash)
        .execute(&pool)
        .await
        .expect("seed device");
    }

    /// Full-control device fixture builder, for tests that need specific
    /// platform/package_manager/agent_version/inventory/available_updates
    /// combinations (the Rust equivalent of Python's tests constructing a
    /// SQLAlchemy Device object directly in setUp).
    #[allow(clippy::too_many_arguments)]
    pub async fn seed_device_full(
        &self,
        id: &str,
        hostname: &str,
        platform: &str,
        package_manager: &str,
        agent_version: &str,
        agent_token_hash: &str,
        available_updates: serde_json::Value,
        inventory: serde_json::Value,
        last_seen: Option<chrono::DateTime<chrono::Utc>>,
    ) {
        let pool = self.pool().await;
        sqlx::query(
            "INSERT INTO devices (id, hostname, platform, package_manager, agent_version, agent_token_hash, \
             available_updates, inventory, last_seen) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, now()))",
        )
        .bind(id)
        .bind(hostname)
        .bind(platform)
        .bind(package_manager)
        .bind(agent_version)
        .bind(agent_token_hash)
        .bind(available_updates)
        .bind(inventory)
        .bind(last_seen)
        .execute(&pool)
        .await
        .expect("seed device");
    }

    /// Direct DB pool for test fixtures/assertions the HTTP API doesn't
    /// expose -- the Rust equivalent of Python's tests touching the
    /// SQLAlchemy session directly.
    pub async fn pool(&self) -> sqlx::PgPool {
        sqlx::PgPool::connect(&self.database_url).await.expect("connect to test db")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        drop_test_db(&self.db_name);
    }
}

fn create_test_db(name: &str) {
    let status = Command::new("sudo")
        .args(["-u", "postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-c", &format!("CREATE DATABASE {name} OWNER fleetview;")])
        .stdout(Stdio::null())
        .status()
        .expect("run psql to create test database");
    assert!(status.success(), "failed to create test database {name}");
}

fn drop_test_db(name: &str) {
    let _ = Command::new("sudo")
        .args(["-u", "postgres", "psql", "-q", "-c", &format!("DROP DATABASE IF EXISTS {name} WITH (FORCE);")])
        .stdout(Stdio::null())
        .status();
}

/// A syntactically valid Fernet key (32 random bytes, base64url-encoded)
/// good enough for tests that need FLEETVIEW_SECRET_KEY set to *something*.
pub fn generate_fernet_key() -> String {
    use base64::engine::general_purpose::URL_SAFE;
    use base64::Engine;
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE.encode(bytes)
}

/// Common request header every non-GET browser-facing endpoint requires
/// (see accounts.rs's require_browser_write) as a lightweight CSRF
/// mitigation independent of the X-CSRF-Token session check.
pub fn fv_header() -> (&'static str, &'static str) {
    ("X-FleetView-Request", "1")
}
