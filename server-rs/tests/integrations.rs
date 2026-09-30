//! Black-box port of server/tests/test_integrations.py's IntegrationsEndpointTests
//! (the ProxmoxConnectorTests/OPNsenseConnectorTests classes are effectively
//! re-covered by src/connectors/*.rs's own real-HTTP verification done during
//! task #58, and manually re-verified end-to-end against real mock servers).
mod common;
use common::{fv_header, TestServer, ADMIN_TOKEN, PASSWORD};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};

async fn setup_admin(server: &TestServer) -> (reqwest::Client, String) {
    let client = server.client();
    let setup = client
        .post(server.url("/api/v1/auth/setup"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"admin_token": ADMIN_TOKEN, "username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(setup.status(), 201, "{}", setup.text().await.unwrap());
    let body: Value = setup.json().await.unwrap();
    (client, body["csrf_token"].as_str().unwrap().to_string())
}

/// A tiny real HTTP server standing in for the Proxmox API, spawned as a
/// Python subprocess (matching the pattern used to verify the connectors
/// for real during task #58).
struct FakeProxmox {
    child: Child,
    pub base_url: String,
}

impl FakeProxmox {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let script = format!(
            r#"
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.headers.get("Authorization") != "PVEAPIToken=fleetview@pve!test=correct-secret":
            self.send_response(401); self.end_headers(); return
        routes = {{
            "/api2/json/nodes": {{"data": [{{"node": "pve1"}}]}},
            "/api2/json/nodes/pve1/qemu": {{"data": [{{"vmid": 100, "name": "web", "status": "running"}}]}},
            "/api2/json/nodes/pve1/lxc": {{"data": [{{"vmid": 200, "name": "db", "status": "stopped"}}]}},
        }}
        body = routes.get(self.path)
        if body is None:
            self.send_response(404); self.end_headers(); return
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

HTTPServer(("127.0.0.1", {port}), Handler).serve_forever()
"#
        );
        let mut child = Command::new("python3").arg("-c").arg(&script).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
        // Wait until the port actually accepts connections.
        for _ in 0..200 {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        if let Some(stdout) = child.stdout.take() {
            std::thread::spawn(move || for _ in BufReader::new(stdout).lines() {});
        }
        FakeProxmox { child, base_url: format!("http://127.0.0.1:{port}") }
    }
}

impl Drop for FakeProxmox {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[tokio::test]
async fn create_syncs_immediately_and_never_exposes_credentials() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let fake = FakeProxmox::start();

    let response = client
        .post(server.url("/api/v1/admin/integrations"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({
            "kind": "proxmox", "name": "Home Proxmox", "base_url": fake.base_url, "verify_tls": false,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.unwrap();
    assert!(body.get("credentials").is_none());
    assert!(body.get("encrypted_credentials").is_none());
    assert!(!body.to_string().contains("correct-secret"));
    assert!(body["last_sync_error"].is_null());
    assert!(!body["last_synced_at"].is_null());
    assert_eq!(body["cached_data"]["vms"][0]["name"], "web");

    let pool = server.pool().await;
    let encrypted: String = sqlx::query_scalar("SELECT encrypted_credentials FROM integrations WHERE id = $1")
        .bind(body["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!encrypted.contains("correct-secret"), "credentials must be encrypted at rest, not stored in plaintext");
}

#[tokio::test]
async fn wrong_credentials_recorded_as_sync_error_not_a_500() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let fake = FakeProxmox::start();

    let response: Value = client
        .post(server.url("/api/v1/admin/integrations"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({
            "kind": "proxmox", "name": "Home Proxmox", "base_url": fake.base_url, "verify_tls": false,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "wrong"},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(response["last_sync_error"].as_str().unwrap().contains("401"));
}

#[tokio::test]
async fn missing_secret_key_returns_409_not_a_crash() {
    // A blank env value tells the harness to unset FLEETVIEW_SECRET_KEY
    // entirely, not just set it to "" (see tests/common/mod.rs).
    let server = TestServer::start_with_env(&[("FLEETVIEW_SECRET_KEY", String::new())]).await;
    let (client, csrf) = setup_admin(&server).await;

    let response = client
        .post(server.url("/api/v1/admin/integrations"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({
            "kind": "proxmox", "name": "X", "base_url": "http://127.0.0.1:1",
            "credentials": {"token_id": "a", "token_secret": "b"},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 409);
    let body: Value = response.json().await.unwrap();
    assert!(body["detail"].as_str().unwrap().contains("FLEETVIEW_SECRET_KEY"));
}

#[tokio::test]
async fn viewer_can_list_but_not_write() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = client
        .post(server.url("/api/v1/admin/users"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"username": "vwr", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created_body: Value = created.json().await.unwrap();
    let pool = server.pool().await;
    sqlx::query("UPDATE users SET must_change_password = false WHERE id = $1").bind(created_body["id"].as_str().unwrap()).execute(&pool).await.unwrap();

    let viewer = server.client();
    let login = viewer
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "vwr", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);

    let list = viewer.get(server.url("/api/v1/admin/integrations")).send().await.unwrap();
    assert_eq!(list.status(), 200);

    let create = viewer
        .post(server.url("/api/v1/admin/integrations"))
        .json(&json!({"kind": "proxmox", "name": "X", "base_url": "http://127.0.0.1:1", "credentials": {"token_id": "a", "token_secret": "b"}}))
        .send()
        .await
        .unwrap();
    assert_eq!(create.status(), 403);
}

#[tokio::test]
async fn update_without_new_credentials_keeps_existing_ones_working() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let fake = FakeProxmox::start();

    let create: Value = client
        .post(server.url("/api/v1/admin/integrations"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({
            "kind": "proxmox", "name": "Home Proxmox", "base_url": fake.base_url, "verify_tls": false,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();

    let update: Value = client
        .put(server.url(&format!("/api/v1/admin/integrations/{id}")))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"kind": "proxmox", "name": "Renamed Proxmox", "base_url": fake.base_url, "verify_tls": false, "credentials": {}}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(update["name"], "Renamed Proxmox");
    assert!(update["last_sync_error"].is_null(), "still synced fine with the old credentials");
}

#[tokio::test]
async fn delete_removes_it() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let fake = FakeProxmox::start();

    let create: Value = client
        .post(server.url("/api/v1/admin/integrations"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({
            "kind": "proxmox", "name": "Home Proxmox", "base_url": fake.base_url, "verify_tls": false,
            "credentials": {"token_id": "fleetview@pve!test", "token_secret": "correct-secret"},
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = create["id"].as_str().unwrap();

    let delete = client.delete(server.url(&format!("/api/v1/admin/integrations/{id}"))).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(delete.status(), 204);

    let list: Vec<Value> = client.get(server.url("/api/v1/admin/integrations")).send().await.unwrap().json().await.unwrap();
    assert!(list.is_empty());
}
