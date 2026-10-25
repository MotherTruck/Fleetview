//! Black-box port of server/tests/test_enrollment_tokens.py's HTTP-observable
//! behavior (the pure token_status logic is unit-tested directly in
//! src/enrollment.rs instead). Drives the real compiled server against a
//! real Postgres database -- see tests/common/mod.rs.
mod common;
use common::{fv_header, TestServer, ADMIN_TOKEN, PASSWORD};
use serde_json::{json, Value};

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
    let csrf = body["csrf_token"].as_str().unwrap().to_string();
    (client, csrf)
}

async fn create_token(client: &reqwest::Client, server: &TestServer, csrf: &str, label: Option<&str>, ttl_minutes: Option<i64>) -> Value {
    let mut payload = json!({});
    if let Some(label) = label {
        payload["label"] = json!(label);
    }
    if let Some(ttl) = ttl_minutes {
        payload["ttl_minutes"] = json!(ttl);
    }
    let response = client
        .post(server.url("/api/v1/admin/enrollment-tokens"))
        .header("X-CSRF-Token", csrf)
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201, "{}", response.text().await.unwrap());
    response.json().await.unwrap()
}

async fn enroll(server: &TestServer, token: &str, hostname: &str) -> reqwest::Response {
    let client = server.client();
    client
        .post(server.url("/api/v1/agent/enroll"))
        .json(&json!({"enrollment_token": token, "hostname": hostname, "agent_version": "0.5.0"}))
        .send()
        .await
        .unwrap()
}

async fn list_tokens(client: &reqwest::Client, server: &TestServer) -> Vec<Value> {
    client.get(server.url("/api/v1/admin/enrollment-tokens")).send().await.unwrap().json().await.unwrap()
}

#[tokio::test]
async fn token_enrolls_exactly_one_device() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, Some("one-shot"), None).await;

    let first = enroll(&server, created["token"].as_str().unwrap(), "one-shot-host").await;
    assert_eq!(first.status(), 201);
    let body: Value = first.json().await.unwrap();
    assert!(body["device_id"].as_str().is_some());
    assert!(body["agent_token"].as_str().is_some());

    let replay = enroll(&server, created["token"].as_str().unwrap(), "intruder").await;
    assert_eq!(replay.status(), 401);

    let devices: Value = client.get(server.url("/api/v1/admin/devices")).send().await.unwrap().json().await.unwrap();
    assert!(
        !devices.as_array().unwrap().iter().any(|d| d["hostname"] == "intruder"),
        "a rejected replay must not create a device"
    );
}

#[tokio::test]
async fn used_token_records_which_device_enrolled() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, Some("tracked"), None).await;
    let result = enroll(&server, created["token"].as_str().unwrap(), "tracked-host").await;
    assert_eq!(result.status(), 201);
    let result_body: Value = result.json().await.unwrap();

    let tokens = list_tokens(&client, &server).await;
    let record = tokens.iter().find(|t| t["id"] == created["id"]).unwrap();
    assert_eq!(record["status"], "used");
    assert_eq!(record["device_id"], result_body["device_id"]);
}

#[tokio::test]
async fn unknown_token_is_rejected() {
    let server = TestServer::start().await;
    let response = enroll(&server, &format!("fv_{}", "x".repeat(43)), "intruder").await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn cannot_revoke_a_used_token_or_a_missing_one() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, None, None).await;
    let enrolled = enroll(&server, created["token"].as_str().unwrap(), "used-then-revoke").await;
    assert_eq!(enrolled.status(), 201);

    let revoke_used = client
        .delete(server.url(&format!("/api/v1/admin/enrollment-tokens/{}", created["id"].as_str().unwrap())))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_used.status(), 409);

    let revoke_missing = client
        .delete(server.url("/api/v1/admin/enrollment-tokens/does-not-exist"))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke_missing.status(), 404);
}

#[tokio::test]
async fn revoked_token_is_rejected() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, None, None).await;
    let revoke = client
        .delete(server.url(&format!("/api/v1/admin/enrollment-tokens/{}", created["id"].as_str().unwrap())))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(revoke.status(), 204);

    let response = enroll(&server, created["token"].as_str().unwrap(), "intruder").await;
    assert_eq!(response.status(), 401);
    let tokens = list_tokens(&client, &server).await;
    let record = tokens.iter().find(|t| t["id"] == created["id"]).unwrap();
    assert_eq!(record["status"], "revoked");
}

#[tokio::test]
async fn plaintext_is_returned_once_and_never_stored_or_listed() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, Some("secret-check"), None).await;
    let token = created["token"].as_str().unwrap();
    assert!(token.starts_with("fv_"));

    let tokens = list_tokens(&client, &server).await;
    let record = tokens.iter().find(|t| t["id"] == created["id"]).unwrap();
    assert!(record.get("token").is_none(), "the list endpoint must never return the plaintext token");

    // The raw DB row must not contain the plaintext token anywhere either.
    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let row: (Option<String>, String) = sqlx::query_as("SELECT label, token_hash FROM enrollment_tokens WHERE id = $1")
        .bind(created["id"].as_str().unwrap())
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_ne!(row.1, token);
    assert!(row.0.as_deref() != Some(token));
}

#[tokio::test]
async fn blank_label_is_stored_as_none() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, Some("   "), None).await;
    assert!(created["label"].is_null());
}

#[tokio::test]
async fn legacy_shared_token_still_works_only_when_configured() {
    let shared = "legacy-shared-token-0123456789";
    let server = TestServer::start_with_env(&[("ENROLLMENT_TOKEN", shared.to_string())]).await;

    let first = enroll(&server, shared, "legacy-1").await;
    assert_eq!(first.status(), 201);
    let second = enroll(&server, shared, "legacy-2").await;
    assert_eq!(second.status(), 201, "legacy shared token must be reusable, unlike per-device tokens");
}

#[tokio::test]
async fn legacy_shared_token_disabled_when_not_configured() {
    let server = TestServer::start().await;
    let response = enroll(&server, "legacy-shared-token-0123456789", "legacy-1").await;
    assert_eq!(response.status(), 401);
}

#[tokio::test]
async fn delete_device_removes_its_jobs_and_metrics_and_unlinks_its_token() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let created = create_token(&client, &server, &csrf, Some("tracked-for-deletion"), None).await;
    let enrolled = enroll(&server, created["token"].as_str().unwrap(), "device-to-delete").await;
    let enrolled_body: Value = enrolled.json().await.unwrap();
    let device_id = enrolled_body["device_id"].as_str().unwrap().to_string();
    let agent_token = enrolled_body["agent_token"].as_str().unwrap().to_string();

    // Give the device a job and a metric sample via real agent-authenticated calls.
    let create_job = client
        .post(server.url(&format!("/api/v1/admin/devices/{device_id}/jobs")))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"type": "SCAN_DEVICE"}))
        .send()
        .await
        .unwrap();
    assert_eq!(create_job.status(), 201);

    let agent = server.client();
    let metrics = sample_metrics_payload();
    let report_metrics = agent
        .post(server.url("/api/v1/agent/metrics"))
        .header("X-Device-Id", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .json(&metrics)
        .send()
        .await
        .unwrap();
    assert_eq!(report_metrics.status(), 204);

    let delete = client
        .delete(server.url(&format!("/api/v1/admin/devices/{device_id}")))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap();
    assert_eq!(delete.status(), 204);

    let get_after_delete = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap();
    assert_eq!(get_after_delete.status(), 404);

    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let job_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE device_id = $1").bind(&device_id).fetch_one(&pool).await.unwrap();
    assert_eq!(job_count, 0);
    let metric_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM metric_samples WHERE device_id = $1").bind(&device_id).fetch_one(&pool).await.unwrap();
    assert_eq!(metric_count, 0);

    let tokens = list_tokens(&client, &server).await;
    let record = tokens.iter().find(|t| t["id"] == created["id"]).unwrap();
    assert!(record.get("status").is_some(), "the enrollment token record itself must survive device deletion");
    assert!(record["device_id"].is_null());
}

#[tokio::test]
async fn delete_missing_device_is_404() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let response = client.delete(server.url("/api/v1/admin/devices/does-not-exist")).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(response.status(), 404);
}

fn sample_metrics_payload() -> Value {
    json!({
        "recorded_at": chrono::Utc::now().to_rfc3339(),
        "cpu_percent": 12.5,
        "memory_used_bytes": 1000,
        "memory_total_bytes": 2000,
        "swap_used_bytes": 0,
        "swap_total_bytes": 0,
        "disk_used_bytes": 1000,
        "disk_total_bytes": 2000,
        "load_1": 0.1,
        "load_5": 0.2,
        "load_15": 0.3,
        "network_receive_bps": 0,
        "network_transmit_bps": 0,
        "network_receive_bytes": 0,
        "network_transmit_bytes": 0,
        "process_count": 42,
        "uptime_seconds": 3600,
        "gpus": [{"index": "0", "name": "Test GPU", "vendor": "NVIDIA"}],
        "top_consumers": [
            {"kind": "process", "pid": 999, "name": "stress", "cpu_percent": 88.0, "memory_bytes": 123456},
            {"kind": "container", "name": "busy-box", "cpu_percent": 12.0, "memory_bytes": 654321},
        ],
    })
}

async fn enroll_device(server: &TestServer, admin: &reqwest::Client, csrf: &str, hostname: &str) -> (String, String) {
    let created = create_token(admin, server, csrf, Some(hostname), None).await;
    let response = enroll(server, created["token"].as_str().unwrap(), hostname).await;
    assert_eq!(response.status(), 201);
    let body: Value = response.json().await.unwrap();
    (body["device_id"].as_str().unwrap().to_string(), body["agent_token"].as_str().unwrap().to_string())
}

#[tokio::test]
async fn report_metrics_with_gpus_does_not_500() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, agent_token) = enroll_device(&server, &client, &csrf, "metrics-host").await;

    let agent = server.client();
    let response = agent
        .post(server.url("/api/v1/agent/metrics"))
        .header("X-Device-Id", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .json(&sample_metrics_payload())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204, "{}", response.text().await.unwrap());

    let detail: Value = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["metrics"]["top_consumers"][0]["name"], "stress");
    assert_eq!(detail["metrics"]["top_consumers"][1]["kind"], "container");
}

/// Regression test for a real bug found via end-to-end testing with the
/// actual Go agent (task #59): its periodic HTTP metrics report used to
/// leave TopConsumers as a nil slice, which Go's encoding/json marshals as
/// literal `null` (not `[]`), and every such report was rejected with 422.
/// The agent was fixed (internal/live/live.go's GatherConsumers is now
/// reused by cmd/fleetview-agent/main.go's metrics ticker), but this
/// confirms the server-side contract the fix relies on: `null` must keep
/// being rejected here exactly like Python's Pydantic schema rejects it
/// (verified independently against the real schema), so a regression in
/// either the agent or a future server change surfaces immediately instead
/// of silently breaking metrics history again.
#[tokio::test]
async fn metrics_report_rejects_null_top_consumers() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, agent_token) = enroll_device(&server, &client, &csrf, "null-top-consumers-host").await;

    let mut payload = sample_metrics_payload();
    payload["top_consumers"] = Value::Null;

    let agent = server.client();
    let response = agent
        .post(server.url("/api/v1/agent/metrics"))
        .header("X-Device-Id", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 422, "a literal null must be rejected, not silently coerced to an empty list");
}

#[tokio::test]
async fn list_and_get_device_report_online_correctly() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, agent_token) = enroll_device(&server, &client, &csrf, "online-check-host").await;

    let agent = server.client();
    let heartbeat = agent
        .post(server.url("/api/v1/agent/heartbeat"))
        .header("X-Device-Id", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(heartbeat.status(), 204);

    let devices: Value = client.get(server.url("/api/v1/admin/devices")).send().await.unwrap().json().await.unwrap();
    let summary = devices.as_array().unwrap().iter().find(|d| d["id"] == device_id).unwrap();
    assert_eq!(summary["online"], true);

    let detail: Value = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["online"], true);
}

#[tokio::test]
async fn report_records_one_compliance_snapshot_per_device_per_day() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, agent_token) = enroll_device(&server, &client, &csrf, "snapshot-host").await;
    let agent = server.client();

    let report_payload = |update_count: usize| {
        json!({
            "hostname": "snapshot-host",
            "agent_version": "0.8.0",
            "scanned_at": chrono::Utc::now().to_rfc3339(),
            "available_updates": (0..update_count).map(|i| json!({"name": format!("pkg{i}"), "security_update": false})).collect::<Vec<_>>(),
        })
    };

    for update_count in [5, 1] {
        let response = agent
            .post(server.url("/api/v1/agent/report"))
            .header("X-Device-Id", &device_id)
            .header("Authorization", format!("Bearer {agent_token}"))
            .json(&report_payload(update_count))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 204);
    }

    let pool = sqlx::PgPool::connect(&server.database_url).await.unwrap();
    let rows: Vec<(i32,)> =
        sqlx::query_as("SELECT update_count FROM compliance_snapshots WHERE device_id = $1").bind(&device_id).fetch_all(&pool).await.unwrap();
    assert_eq!(rows.len(), 1, "same UTC day must not add a second snapshot row");
    // Upserts, not write-once: the snapshot reflects the LATEST report of
    // the day, not the first. Write-once meant a day's `online` froze at
    // whatever it was on the first report -- and the only way this write
    // happens at all is a report succeeding, which itself proves the device
    // was online right then, so practically every day came out `online =
    // true` regardless of how much of the rest of the day it then spent
    // offline (the real bug this test used to enshrine as correct).
    assert_eq!(rows[0].0, 1, "a later report the same day must overwrite the snapshot, not be ignored");
}

#[tokio::test]
async fn vulnerability_exposure_flags_packages_with_a_listening_process() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, agent_token) = enroll_device(&server, &client, &csrf, "exposure-host").await;
    let agent = server.client();

    let payload = json!({
        "scanned_at": chrono::Utc::now().to_rfc3339(),
        "vulnerabilities": [
            {"vulnerability_id": "CVE-100", "package": "openssh-server", "severity": "HIGH"},
            {"vulnerability_id": "CVE-200", "package": "some-library", "severity": "LOW"},
        ],
        "listening_ports": [
            {"port": 22, "protocol": "tcp", "process": "sshd"},
            {"port": 68, "protocol": "udp", "process": "dhclient"},
        ],
    });
    let response = agent
        .post(server.url("/api/v1/agent/vulnerabilities"))
        .header("X-Device-Id", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    let detail: Value = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap().json().await.unwrap();
    let findings: std::collections::HashMap<String, Value> =
        detail["vulnerabilities"].as_array().unwrap().iter().map(|v| (v["package"].as_str().unwrap().to_string(), v.clone())).collect();
    assert_eq!(findings["openssh-server"]["exposure"], "listening");
    assert_eq!(findings["openssh-server"]["exposure_detail"], json!(["tcp/22"]));
    assert_eq!(findings["some-library"]["exposure"], "unknown");
    assert_eq!(findings["some-library"]["exposure_detail"], json!([]));
    assert_eq!(detail["vulnerability_exposed_count"], 1);
    assert_eq!(detail["listening_ports"].as_array().unwrap().len(), 2);

    let devices: Value = client.get(server.url("/api/v1/admin/devices")).send().await.unwrap().json().await.unwrap();
    let summary = devices.as_array().unwrap().iter().find(|d| d["id"] == device_id).unwrap();
    assert_eq!(summary["vulnerability_exposed_count"], 1);
    assert!(summary.get("vulnerabilities").is_none(), "list view must stay lightweight");
    assert!(summary.get("listening_ports").is_none());
}

#[tokio::test]
async fn vulnerability_exposure_defaults_to_unknown_with_no_listening_ports() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, agent_token) = enroll_device(&server, &client, &csrf, "no-ports-host").await;
    let agent = server.client();

    let payload = json!({
        "scanned_at": chrono::Utc::now().to_rfc3339(),
        "vulnerabilities": [{"vulnerability_id": "CVE-300", "package": "curl", "severity": "LOW"}],
        "listening_ports": [],
    });
    let response = agent
        .post(server.url("/api/v1/agent/vulnerabilities"))
        .header("X-Device-Id", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 204);

    let detail: Value = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["vulnerabilities"][0]["exposure"], "unknown");
    assert_eq!(detail["vulnerability_exposed_count"], 0);
    assert_eq!(detail["listening_ports"], json!([]));
}

#[tokio::test]
async fn new_device_uses_fleet_default_intervals_until_overridden() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let (device_id, _agent_token) = enroll_device(&server, &client, &csrf, "fleet-defaults-host").await;

    let update_fleet = client
        .put(server.url("/api/v1/admin/settings"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"default_metrics_interval_seconds": 45, "default_inventory_interval_seconds": 1800}))
        .send()
        .await
        .unwrap();
    assert_eq!(update_fleet.status(), 200);

    let detail: Value = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail["agent_settings"]["metrics_interval_seconds"], 45);
    assert_eq!(detail["agent_settings"]["inventory_interval_seconds"], 1800);

    let override_device = client
        .put(server.url(&format!("/api/v1/admin/devices/{device_id}/settings")))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"metrics_interval_seconds": 120, "inventory_interval_seconds": 1800}))
        .send()
        .await
        .unwrap();
    assert_eq!(override_device.status(), 200, "{}", override_device.text().await.unwrap());

    let detail2: Value = client.get(server.url(&format!("/api/v1/admin/devices/{device_id}"))).send().await.unwrap().json().await.unwrap();
    assert_eq!(detail2["agent_settings"]["metrics_interval_seconds"], 120, "an explicit per-device override must win over the fleet default");
}

#[tokio::test]
async fn fleet_settings_endpoint_round_trips() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let updated: Value = client
        .put(server.url("/api/v1/admin/settings"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"default_metrics_interval_seconds": 30, "default_inventory_interval_seconds": 600}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["default_metrics_interval_seconds"], 30);
    assert_eq!(updated["default_inventory_interval_seconds"], 600);

    let fetched: Value = client.get(server.url("/api/v1/admin/settings")).send().await.unwrap().json().await.unwrap();
    assert_eq!(fetched, updated);
}

#[tokio::test]
async fn package_requires_at_least_one_platform_identifier() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;
    let response = client
        .post(server.url("/api/v1/admin/packages"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"name": "Nothing configured"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn package_crud_round_trips() {
    let server = TestServer::start().await;
    let (client, csrf) = setup_admin(&server).await;

    let created: Value = client
        .post(server.url("/api/v1/admin/packages"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({
            "name": "Firefox", "version": "1.0", "category": "Browsers",
            "pacman_name": "firefox", "apt_name": "firefox-esr", "winget_id": "Mozilla.Firefox",
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["name"], "Firefox");
    assert_eq!(created["winget_id"], "Mozilla.Firefox");
    let id = created["id"].as_str().unwrap().to_string();

    let listed: Value = client.get(server.url("/api/v1/admin/packages")).send().await.unwrap().json().await.unwrap();
    assert!(listed.as_array().unwrap().iter().any(|p| p["id"] == id));

    let updated: Value = client
        .put(server.url(&format!("/api/v1/admin/packages/{id}")))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"name": "Firefox", "version": "2.0", "pacman_name": "firefox"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["version"], "2.0");
    assert_eq!(updated["apt_name"], "", "fields left out of the update payload must be cleared, not merged");

    let missing = client
        .put(server.url("/api/v1/admin/packages/does-not-exist"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"name": "X", "pacman_name": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing.status(), 404);

    let delete = client.delete(server.url(&format!("/api/v1/admin/packages/{id}"))).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(delete.status(), 204);

    let delete_again = client.delete(server.url(&format!("/api/v1/admin/packages/{id}"))).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(delete_again.status(), 404);
}
