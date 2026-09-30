//! Black-box port of the remaining server/tests/test_fleet_features.py
//! scenarios not already covered elsewhere: UNINSTALL_PACKAGE/DOCKER_CONTAINER_ACTION
//! job validation, unsupported-scan-platform, report scope/date handling, and
//! the legacy X-Admin-Token agent-poll path.
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
    (client, body["csrf_token"].as_str().unwrap().to_string())
}

async fn create_job(client: &reqwest::Client, server: &TestServer, csrf: &str, device: &str, job_type: &str, options: Value) -> reqwest::Response {
    client
        .post(server.url(&format!("/api/v1/admin/devices/{device}/jobs")))
        .header("X-CSRF-Token", csrf)
        .json(&json!({"type": job_type, "options": options}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn uninstall_requires_confirmation_and_literal_name() {
    let server = TestServer::start().await;
    server.seed_device_full("one", "debian", "linux", "apt", "0.20.0", "unused", json!([]), json!({}), None).await;
    let (client, csrf) = setup_admin(&server).await;

    for bad_options in [
        json!({"package": "htop"}), // missing confirmed
        json!({"package": "--help", "confirmed": true}),
        json!({"package": "foo*", "confirmed": true}),
        json!({"package": "foo bar", "confirmed": true}),
        json!({"package": ["foo"], "confirmed": true}),
    ] {
        let response = create_job(&client, &server, &csrf, "one", "UNINSTALL_PACKAGE", bad_options.clone()).await;
        assert_eq!(response.status(), 400, "options {bad_options} should be rejected");
    }

    let ok = create_job(&client, &server, &csrf, "one", "UNINSTALL_PACKAGE", json!({"package": "htop", "confirmed": true})).await;
    assert_eq!(ok.status(), 201, "{}", ok.text().await.unwrap());

    let duplicate = create_job(&client, &server, &csrf, "one", "UNINSTALL_PACKAGE", json!({"package": "htop", "confirmed": true})).await;
    assert_eq!(duplicate.status(), 409);
}

#[tokio::test]
async fn docker_actions_require_known_container_and_confirmation() {
    let server = TestServer::start().await;
    let container_id = "abcdef012345";
    server
        .seed_device_full(
            "one", "debian", "linux", "apt", "0.15.0", "unused",
            json!([]),
            json!({"docker_available": true, "docker_containers": [{"id": container_id}]}),
            None,
        )
        .await;
    let (client, csrf) = setup_admin(&server).await;
    let options = json!({"action": "restart", "container_id": container_id, "confirmed": true});

    for invalid in [
        json!({"action": "restart", "container_id": container_id, "confirmed": false}),
        json!({"action": "exec", "container_id": container_id, "confirmed": true}),
        json!({"action": "restart", "container_id": "different-id", "confirmed": true}),
        json!({"action": "restart", "container_id": container_id, "confirmed": true, "extra": "value"}),
    ] {
        let response = create_job(&client, &server, &csrf, "one", "DOCKER_CONTAINER_ACTION", invalid.clone()).await;
        assert_eq!(response.status(), 400, "options {invalid} should be rejected");
    }

    let job: Value = create_job(&client, &server, &csrf, "one", "DOCKER_CONTAINER_ACTION", options.clone()).await.json().await.unwrap();
    assert_eq!(job["options"], options);

    let duplicate = create_job(&client, &server, &csrf, "one", "DOCKER_CONTAINER_ACTION", options).await;
    assert_eq!(duplicate.status(), 409);
}

#[tokio::test]
async fn docker_action_rejected_below_version_gate() {
    let server = TestServer::start().await;
    let container_id = "abcdef012345";
    server
        .seed_device_full(
            "one", "debian", "linux", "apt", "0.14.0", "unused",
            json!([]),
            json!({"docker_available": true, "docker_containers": [{"id": container_id}]}),
            None,
        )
        .await;
    let (client, csrf) = setup_admin(&server).await;
    let response = create_job(
        &client, &server, &csrf, "one", "DOCKER_CONTAINER_ACTION",
        json!({"action": "restart", "container_id": container_id, "confirmed": true}),
    )
    .await;
    assert_eq!(response.status(), 400, "an agent below 0.15.0 must be rejected before the container-known check even runs");
}

#[tokio::test]
async fn unsupported_scan_platform_rejects_schedule() {
    let server = TestServer::start().await;
    server.seed_device_full("one", "ubuntu-box", "linux", "apt", "0.20.0", "unused", json!([]), json!({}), None).await;
    let (client, csrf) = setup_admin(&server).await;
    // apt + Ubuntu (not Debian) is unsupported for automatic scan scheduling.
    let response = client
        .put(server.url("/api/v1/admin/devices/one/vulnerability-schedule"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"interval_hours": 24}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn report_scope_and_inclusive_dates() {
    let server = TestServer::start().await;
    server.seed_device_full("one", "debian", "linux", "apt", "0.20.0", "unused", json!([]), json!({}), None).await;
    server.seed_device_full("two", "other", "linux", "apt", "0.20.0", "unused2", json!([]), json!({}), None).await;
    let (client, csrf) = setup_admin(&server).await;
    let _ = csrf;

    let pool = server.pool().await;
    for device_id in ["one", "two"] {
        for day in ["2026-01-01", "2026-02-01", "2026-03-01"] {
            sqlx::query(
                "INSERT INTO compliance_snapshots (device_id, snapshot_date, update_count, vulnerability_count, online) \
                 VALUES ($1, $2, 2, 3, true)",
            )
            .bind(device_id)
            .bind(day)
            .execute(&pool)
            .await
            .unwrap();
        }
    }

    let scoped: Vec<Value> = client
        .get(server.url("/api/v1/admin/reports/history?device_id=one&start=2026-01-01&end=2026-03-01"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(scoped.len(), 3);
    assert!(scoped.iter().all(|row| row["device_count"] == 1));
    assert_eq!(scoped[0]["total_updates_needed"], 2);

    let fleet_wide: Vec<Value> = client
        .get(server.url("/api/v1/admin/reports/history?start=2026-01-01&end=2026-03-01"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(fleet_wide[0]["device_count"], 2);

    let reversed = client.get(server.url("/api/v1/admin/reports/history?start=2026-03-01&end=2026-01-01")).send().await.unwrap();
    assert_eq!(reversed.status(), 400);
    let missing_end = client.get(server.url("/api/v1/admin/reports/history?start=2026-01-01")).send().await.unwrap();
    assert_eq!(missing_end.status(), 400);

    let empty_range: Vec<Value> =
        client.get(server.url("/api/v1/admin/reports/history?device_id=one&start=2025-01-01&end=2025-02-01")).send().await.unwrap().json().await.unwrap();
    assert!(empty_range.is_empty());

    let unknown_device = client.get(server.url("/api/v1/admin/reports/history?device_id=missing")).send().await.unwrap();
    assert_eq!(unknown_device.status(), 404);
}

#[tokio::test]
async fn legacy_admin_token_agent_poll_and_validation() {
    let server = TestServer::start().await;
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(b"agent-test"))
    };
    server.seed_device_full("one", "debian", "linux", "apt", "0.20.0", &token_hash, json!([]), json!({}), None).await;
    // scan_supported() requires apt + a Debian os_name (or pacman); seed_device_full
    // doesn't take os_name, so set it directly for the scan-schedule calls below.
    sqlx::query("UPDATE devices SET os_name = 'Debian GNU/Linux' WHERE id = 'one'").execute(&server.pool().await).await.unwrap();

    // Before setup, the legacy X-Admin-Token bootstraps a Viewer -- but this
    // endpoint requires Admin (require_real_admin), and the legacy path
    // never satisfies an Admin-role check, so this stays 401/403, not 200.
    let anon = server.client();
    let url = server.url("/api/v1/admin/devices/one/vulnerability-schedule");
    let no_auth = anon.get(&url).send().await.unwrap();
    assert_eq!(no_auth.status(), 401);

    let admin_headers = [("X-Admin-Token", "test-admin-token")];
    let mut req = anon.get(&url);
    for (k, v) in admin_headers {
        req = req.header(k, v);
    }
    let legacy_get = req.send().await.unwrap();
    // GET only needs Viewer, and the legacy bootstrap token satisfies Viewer
    // pre-setup, so this succeeds (device has no schedule row yet -> defaults).
    assert_eq!(legacy_get.status(), 200);

    let bad_interval =
        anon.put(&url).header("X-Admin-Token", "test-admin-token").json(&json!({"interval_hours": -1})).send().await.unwrap();
    assert_eq!(bad_interval.status(), 400);

    let ok = anon.put(&url).header("X-Admin-Token", "test-admin-token").json(&json!({"interval_hours": 24})).send().await.unwrap();
    assert_eq!(ok.status(), 200);

    let pool = server.pool().await;
    sqlx::query("UPDATE vulnerability_schedules SET next_run_at = now() - interval '1 hour' WHERE device_id = 'one'").execute(&pool).await.unwrap();

    let agent = server.client();
    let next: Value = agent
        .get(server.url("/api/v1/agent/jobs/next"))
        .header("X-Device-Id", "one")
        .header("Authorization", "Bearer agent-test")
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(next["type"], "SCAN_VULNERABILITIES");

    let empty = agent.get(server.url("/api/v1/agent/jobs/next")).header("X-Device-Id", "one").header("Authorization", "Bearer agent-test").send().await.unwrap();
    assert_eq!(empty.status(), 204);
}
