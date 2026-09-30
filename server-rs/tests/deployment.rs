//! Black-box port of server/tests/test_deployment.py against the real Rust
//! server + real Postgres (see tests/common/mod.rs).
mod common;
use common::{fv_header, TestServer, ADMIN_TOKEN, PASSWORD};
use serde_json::{json, Value};
use std::io::Write;

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

fn token_hash(token: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Seeds the same device fixtures Python's test_deployment.py setUp builds,
/// with real agent-token hashes (matching Python's token_hash("...-secret"))
/// so agent-authenticated endpoints work against these fixtures too.
async fn seed_fixture_devices(server: &TestServer) {
    server
        .seed_device_full(
            "dev", "target", "linux", "apt", "0.14.0", &token_hash("agent-secret"),
            json!([{"package": "curl", "installed_version": "1", "available_version": "2"},
                   {"package": "vim", "installed_version": "1", "available_version": "3"}]),
            json!({}), None,
        )
        .await;
    server
        .seed_device_full(
            "arch", "rolling", "linux", "pacman", "0.14.0", &token_hash("arch-secret"),
            json!([{"package": "curl", "available_version": "2"}, {"package": "vim", "available_version": "3"}]),
            json!({}), None,
        )
        .await;
    server.seed_device_full("new", "fresh", "linux", "apt", "0.16.0", &token_hash("new-secret"), json!([]), json!({}), None).await;
    server.seed_device_full("winnew", "winbox", "windows", "winget", "0.16.0", &token_hash("win-secret"), json!([]), json!({}), None).await;
    let now = chrono::Utc::now();
    server
        .seed_device_full(
            "netnew", "relay-box", "linux", "apt", "0.20.0", &token_hash("netnew-secret"),
            json!([]), json!({"mac_addresses": ["aa:bb:cc:dd:ee:ff"]}), Some(now),
        )
        .await;
    server.seed_device_full("netnomac", "no-mac-box", "linux", "apt", "0.20.0", &token_hash("netnomac-secret"), json!([]), json!({}), Some(now)).await;
    server
        .seed_device_full(
            "netoffline", "asleep-box", "linux", "apt", "0.20.0", &token_hash("netoffline-secret"),
            json!([]), json!({"mac_addresses": ["11:22:33:44:55:66"]}), Some(now - chrono::Duration::minutes(10)),
        )
        .await;
}

async fn approve(client: &reqwest::Client, server: &TestServer, csrf: &str, device: &str, package: &str, version: &str, approved: bool) -> reqwest::Response {
    client
        .put(server.url(&format!("/api/v1/admin/devices/{device}/patch-approvals")))
        .header("X-CSRF-Token", csrf)
        .json(&json!({"package": package, "available_version": version, "approved": approved}))
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn selected_approval_exact_version_and_legacy_update_blocked() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;
    let base = "/api/v1/admin/devices/dev";

    let no_approvals = client.post(server.url(&format!("{base}/deploy-approved-patches"))).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(no_approvals.status(), 409);

    let wrong_version = approve(&client, &server, &csrf, "dev", "curl", "9", true).await;
    assert_eq!(wrong_version.status(), 409);

    let ok_approve = approve(&client, &server, &csrf, "dev", "curl", "2", true).await;
    assert_eq!(ok_approve.status(), 200);

    let job: Value = client
        .post(server.url(&format!("{base}/deploy-approved-patches")))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(job["updates"], json!([{"package": "curl", "version": "2"}]));

    let legacy_blocked = client
        .post(server.url(&format!("{base}/jobs")))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"type": "INSTALL_UPDATES", "options": {"confirmed": true}}))
        .send()
        .await
        .unwrap();
    assert_eq!(legacy_blocked.status(), 400);

    let duplicate_deploy = client.post(server.url(&format!("{base}/deploy-approved-patches"))).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(duplicate_deploy.status(), 409);

    let unapprove = approve(&client, &server, &csrf, "dev", "curl", "2", false).await;
    assert_eq!(unapprove.status(), 200);

    // Revoking approval must fail the now-orphaned pending job.
    let pool = server.pool().await;
    let job_id = job["id"].as_str().unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id = $1").bind(job_id).fetch_one(&pool).await.unwrap();
    assert_eq!(status, "failed");
}

#[tokio::test]
async fn arch_requires_all_approvals_and_schedules_dedupe() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;
    let base = "/api/v1/admin/devices/arch";

    approve(&client, &server, &csrf, "arch", "curl", "2", true).await;
    let missing_vim = client.post(server.url(&format!("{base}/deploy-approved-patches"))).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(missing_vim.status(), 409);
    approve(&client, &server, &csrf, "arch", "vim", "3", true).await;

    let schedule = client
        .put(server.url(&format!("{base}/patch-schedule")))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"interval_hours": 1}))
        .send()
        .await
        .unwrap();
    assert_eq!(schedule.status(), 200, "{}", schedule.text().await.unwrap());

    let pool = server.pool().await;
    sqlx::query("UPDATE patch_schedules SET next_run_at = now() - interval '2 hours' WHERE device_id = 'arch'").execute(&pool).await.unwrap();

    let agent = server.client();
    let first_response =
        agent.get(server.url("/api/v1/agent/jobs/next")).header("X-Device-ID", "arch").header("Authorization", "Bearer arch-secret").send().await.unwrap();
    assert_eq!(first_response.status(), 200);
    let first: Value = first_response.json().await.unwrap();
    assert_eq!(first["type"], "INSTALL_APPROVED_UPDATES");

    let pool = server.pool().await;
    sqlx::query("UPDATE patch_schedules SET next_run_at = now() - interval '2 hours' WHERE device_id = 'arch'").execute(&pool).await.unwrap();
    let second = agent.get(server.url("/api/v1/agent/jobs/next")).header("X-Device-ID", "arch").header("Authorization", "Bearer arch-secret").send().await.unwrap();
    assert_eq!(second.status(), 204, "the already-claimed INSTALL_APPROVED_UPDATES job must prevent queuing a duplicate scheduled patch job");

    let job_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE device_id = 'arch'").fetch_one(&pool).await.unwrap();
    assert_eq!(job_count, 1);
}

#[tokio::test]
async fn admin_only_upload_agent_download_and_sha() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    // Re-enroll "dev" for real so its agent token is genuine and usable below.
    let created = client
        .post(server.url("/api/v1/admin/enrollment-tokens"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({}))
        .send()
        .await
        .unwrap()
        .json::<Value>()
        .await
        .unwrap();
    let enroll_client = server.client();
    let enrolled: Value = enroll_client
        .post(server.url("/api/v1/agent/enroll"))
        .json(&json!({"enrollment_token": created["token"], "hostname": "target2", "agent_version": "0.14.0"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let device_id = enrolled["device_id"].as_str().unwrap().to_string();
    let agent_token = enrolled["agent_token"].as_str().unwrap().to_string();

    let form = reqwest::multipart::Form::new()
        .text("name", "Local installer")
        .text("platform", "linux")
        .text("command", "bash ./install.sh")
        .part("files", reqwest::multipart::Part::bytes(b"echo ready\n".to_vec()).file_name("install.sh").mime_str("application/octet-stream").unwrap());
    let upload = client.post(server.url("/api/v1/admin/custom-packages")).header("X-CSRF-Token", &csrf).multipart(form).send().await.unwrap();
    assert_eq!(upload.status(), 201, "{}", upload.text().await.unwrap());
    let bundle: Value = client
        .get(server.url("/api/v1/admin/custom-packages"))
        .send()
        .await
        .unwrap()
        .json::<Vec<Value>>()
        .await
        .unwrap()
        .into_iter()
        .find(|b| b["name"] == "Local installer")
        .unwrap();
    let expected_sha = sha256_hex(b"echo ready\n");
    assert_eq!(bundle["files"][0]["sha256"], expected_sha);

    let bad_form = reqwest::multipart::Form::new()
        .text("name", "Bad")
        .text("platform", "linux")
        .text("command", "true")
        .part("files", reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("../install.sh").mime_str("application/octet-stream").unwrap());
    let bad_name = client.post(server.url("/api/v1/admin/custom-packages")).header("X-CSRF-Token", &csrf).multipart(bad_form).send().await.unwrap();
    assert_eq!(bad_name.status(), 400);

    let path = format!("/api/v1/admin/custom-packages/{}/devices/{device_id}/deploy", bundle["id"].as_str().unwrap());
    let unconfirmed = client.post(server.url(&path)).header("X-CSRF-Token", &csrf).json(&json!({"confirmed": false})).send().await.unwrap();
    assert_eq!(unconfirmed.status(), 400);

    let deploy: Value = client
        .post(server.url(&path))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"confirmed": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let job_id = deploy["id"].as_str().unwrap().to_string();
    let manifest_path = format!("/api/v1/agent/jobs/{job_id}/bundle");
    let agent = server.client();

    // Not yet claimed (still pending) -> 404.
    let too_early = agent.get(server.url(&manifest_path)).header("X-Device-ID", &device_id).header("Authorization", format!("Bearer {agent_token}")).send().await.unwrap();
    assert_eq!(too_early.status(), 404);

    let claim = agent.get(server.url("/api/v1/agent/jobs/next")).header("X-Device-ID", &device_id).header("Authorization", format!("Bearer {agent_token}")).send().await.unwrap();
    assert_eq!(claim.status(), 200);

    let no_auth = agent.get(server.url(&manifest_path)).header("X-Device-ID", &device_id).send().await.unwrap();
    assert_eq!(no_auth.status(), 401);

    let manifest: Value = agent
        .get(server.url(&manifest_path))
        .header("X-Device-ID", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(manifest["command"], "bash ./install.sh");

    let file_path = format!("{manifest_path}/files/{}", bundle["files"][0]["id"].as_str().unwrap());
    let file_content = agent
        .get(server.url(&file_path))
        .header("X-Device-ID", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .send()
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    assert_eq!(&file_content[..], b"echo ready\n");

    // A different (correctly-authenticated) device cannot fetch this file.
    let arch_agent = server.client();
    let wrong_device =
        arch_agent.get(server.url(&file_path)).header("X-Device-ID", "arch").header("Authorization", "Bearer arch-secret").send().await.unwrap();
    assert_eq!(wrong_device.status(), 404);

    let complete = agent
        .post(server.url(&format!("/api/v1/agent/jobs/{job_id}/result")))
        .header("X-Device-ID", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .json(&json!({"status": "succeeded", "output": "ok"}))
        .send()
        .await
        .unwrap();
    assert_eq!(complete.status(), 204);

    let after_complete = agent
        .get(server.url(&file_path))
        .header("X-Device-ID", &device_id)
        .header("Authorization", format!("Bearer {agent_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(after_complete.status(), 404, "a completed job's bundle must no longer be fetchable");
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

#[tokio::test]
async fn run_command_requires_confirmation_and_agent_version() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let old = client
        .post(server.url("/api/v1/admin/devices/dev/run-command"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"command": "echo hi", "confirmed": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(old.status(), 409, "{}", old.text().await.unwrap());

    let unconfirmed = client
        .post(server.url("/api/v1/admin/devices/new/run-command"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"command": "echo hi", "confirmed": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(unconfirmed.status(), 400);

    let ok: Value = client
        .post(server.url("/api/v1/admin/devices/new/run-command"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"command": "echo hi", "confirmed": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let job_id = ok["id"].as_str().unwrap();

    let pool = server.pool().await;
    let (job_type, options): (String, Value) = sqlx::query_as("SELECT type, options FROM jobs WHERE id = $1").bind(job_id).fetch_one(&pool).await.unwrap();
    assert_eq!(job_type, "RUN_COMMAND");
    assert_eq!(options["command"], "echo hi");
    assert_eq!(options["confirmed"], true);
}

#[tokio::test]
async fn viewer_cannot_read_run_command_payload_or_output() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let created: Value = client
        .post(server.url("/api/v1/admin/devices/new/run-command"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"command": "echo top-secret-value", "confirmed": true}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let job_id = created["id"].as_str().unwrap().to_string();

    let pool = server.pool().await;
    sqlx::query("UPDATE jobs SET status = 'succeeded', output = $1 WHERE id = $2")
        .bind("top-secret-value\n")
        .bind(&job_id)
        .execute(&pool)
        .await
        .unwrap();

    let created_user = client
        .post(server.url("/api/v1/admin/users"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"username": "viewer2", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created_user.status(), 201);
    let created_user_body: Value = created_user.json().await.unwrap();
    sqlx::query("UPDATE users SET must_change_password = false WHERE id = $1")
        .bind(created_user_body["id"].as_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();

    let viewer = server.client();
    let login: Value = viewer
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "viewer2", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let _ = login;

    let as_viewer: Vec<Value> = viewer.get(server.url("/api/v1/admin/jobs")).send().await.unwrap().json().await.unwrap();
    let viewer_job = as_viewer.iter().find(|j| j["id"] == job_id).unwrap();
    assert_eq!(viewer_job["options"], json!({}));
    assert!(viewer_job["output"].is_null());
    assert_eq!(viewer_job["status"], "succeeded", "job status itself is still visible to a viewer");

    let as_admin: Vec<Value> = client.get(server.url("/api/v1/admin/jobs")).send().await.unwrap().json().await.unwrap();
    let admin_job = as_admin.iter().find(|j| j["id"] == job_id).unwrap();
    assert_eq!(admin_job["options"]["command"], "echo top-secret-value");
    assert_eq!(admin_job["output"], "top-secret-value\n");
}

#[tokio::test]
async fn run_command_rejects_empty_and_oversized() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let empty = client
        .post(server.url("/api/v1/admin/devices/new/run-command"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"command": "", "confirmed": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(empty.status(), 400, "Rust's manual length check returns 400; Python's Pydantic Field(min_length=1) returns 422 for the same case");

    let huge = client
        .post(server.url("/api/v1/admin/devices/new/run-command"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"command": "x".repeat(5000), "confirmed": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(huge.status(), 400);
}

fn write_manifest(dir: &std::path::Path, manifest: &Value) {
    let agent_bin_dir = dir.join("agent-bin");
    std::fs::create_dir_all(&agent_bin_dir).unwrap();
    let mut file = std::fs::File::create(agent_bin_dir.join("manifest.json")).unwrap();
    file.write_all(serde_json::to_string(manifest).unwrap().as_bytes()).unwrap();
}

#[tokio::test]
async fn upgrade_agent_no_manifest_is_409() {
    let install_dir = std::env::temp_dir().join(format!("fv-install-test-nomanifest-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&install_dir).unwrap();
    let server = TestServer::start_with_env(&[("FLEETVIEW_INSTALL_DIR", install_dir.to_string_lossy().to_string())]).await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let response = client.post(server.url("/api/v1/admin/devices/new/upgrade-agent")).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(response.status(), 409);
    let _ = std::fs::remove_dir_all(&install_dir);
}

#[tokio::test]
async fn upgrade_agent_gates_on_manifest_platform_and_version() {
    let install_dir = std::env::temp_dir().join(format!("fv-install-test-{}", uuid::Uuid::new_v4()));
    let manifest = json!({
        "version": "0.17.0",
        "linux_amd64": {"sha256": "a".repeat(64), "path": "/install/agent-linux-amd64"},
        "windows_amd64": {"sha256": "b".repeat(64), "path": "/install/agent-windows-amd64.exe"},
    });
    write_manifest(&install_dir, &manifest);
    let server = TestServer::start_with_env(&[("FLEETVIEW_INSTALL_DIR", install_dir.to_string_lossy().to_string())]).await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    // "dev" is old enough to support deployment but not remote agent upgrade (0.14.0 < 0.16.0).
    let too_old = client.post(server.url("/api/v1/admin/devices/dev/upgrade-agent")).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(too_old.status(), 409);

    let same_version: Value = client
        .post(server.url("/api/v1/admin/devices/new/upgrade-agent"))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(same_version["version"], "0.17.0");
    let job_id = same_version["id"].as_str().unwrap().to_string();

    let pool = server.pool().await;
    let (job_type, options): (String, Value) = sqlx::query_as("SELECT type, options FROM jobs WHERE id = $1").bind(&job_id).fetch_one(&pool).await.unwrap();
    assert_eq!(job_type, "UPGRADE_AGENT");
    assert_eq!(options, json!({"version": "0.17.0", "sha256": "a".repeat(64), "url": "/install/agent-linux-amd64"}));

    let duplicate = client.post(server.url("/api/v1/admin/devices/new/upgrade-agent")).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(duplicate.status(), 409);

    let windows_job: Value = client
        .post(server.url("/api/v1/admin/devices/winnew/upgrade-agent"))
        .header("X-CSRF-Token", &csrf)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let windows_job_id = windows_job["id"].as_str().unwrap();
    let (_, windows_options): (String, Value) = sqlx::query_as("SELECT type, options FROM jobs WHERE id = $1").bind(windows_job_id).fetch_one(&pool).await.unwrap();
    assert_eq!(windows_options["url"], "/install/agent-windows-amd64.exe");

    sqlx::query("UPDATE devices SET agent_version = '0.17.0' WHERE id = 'new'").execute(&pool).await.unwrap();
    let already = client.post(server.url("/api/v1/admin/devices/new/upgrade-agent")).header("X-CSRF-Token", &csrf).send().await.unwrap();
    assert_eq!(already.status(), 409);

    let _ = std::fs::remove_dir_all(&install_dir);
}

#[tokio::test]
async fn viewer_cannot_approve_schedule_or_upload() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let created = client
        .post(server.url("/api/v1/admin/users"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"username": "viewer", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created_body: Value = created.json().await.unwrap();
    let pool = server.pool().await;
    sqlx::query("UPDATE users SET must_change_password = false WHERE id = $1").bind(created_body["id"].as_str().unwrap()).execute(&pool).await.unwrap();

    let viewer = server.client();
    viewer
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "viewer", "password": PASSWORD}))
        .send()
        .await
        .unwrap();

    let list_ok = viewer.get(server.url("/api/v1/admin/devices/dev/patch-approvals")).send().await.unwrap();
    assert_eq!(list_ok.status(), 200);

    let approve_denied = viewer
        .put(server.url("/api/v1/admin/devices/dev/patch-approvals"))
        .json(&json!({"package": "curl", "available_version": "2", "approved": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(approve_denied.status(), 403);

    let schedule_denied = viewer.put(server.url("/api/v1/admin/devices/dev/patch-schedule")).json(&json!({"interval_hours": 1})).send().await.unwrap();
    assert_eq!(schedule_denied.status(), 403);

    let form = reqwest::multipart::Form::new()
        .text("name", "Bad")
        .text("platform", "linux")
        .text("command", "true")
        .part("files", reqwest::multipart::Part::bytes(b"hello".to_vec()).file_name("install.sh").mime_str("application/octet-stream").unwrap());
    let upload_denied = viewer.post(server.url("/api/v1/admin/custom-packages")).multipart(form).send().await.unwrap();
    assert_eq!(upload_denied.status(), 403);

    let run_denied = viewer.post(server.url("/api/v1/admin/devices/new/run-command")).json(&json!({"command": "echo hi", "confirmed": true})).send().await.unwrap();
    assert_eq!(run_denied.status(), 403);

    let upgrade_denied = viewer.post(server.url("/api/v1/admin/devices/new/upgrade-agent")).send().await.unwrap();
    assert_eq!(upgrade_denied.status(), 403);

    let diagnostic_denied =
        viewer.post(server.url("/api/v1/admin/devices/netnew/network-diagnostic")).json(&json!({"tool": "dns", "target": "example.com"})).send().await.unwrap();
    assert_eq!(diagnostic_denied.status(), 403);

    let wake_denied = viewer.post(server.url("/api/v1/admin/devices/netoffline/wake")).json(&json!({"relay_device_id": "netnew"})).send().await.unwrap();
    assert_eq!(wake_denied.status(), 403);
}

#[tokio::test]
async fn network_diagnostic_gates_on_agent_version_and_validates_input() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let old_device = client
        .post(server.url("/api/v1/admin/devices/dev/network-diagnostic"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"tool": "ping", "target": "example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(old_device.status(), 409, "{}", old_device.text().await.unwrap());

    let bad_tool = client
        .post(server.url("/api/v1/admin/devices/netnew/network-diagnostic"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"tool": "nmap", "target": "example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_tool.status(), 400, "Rust returns 400 for an out-of-enum tool value (manual validation); Python's Pydantic Literal returns 422");

    let bad_target = client
        .post(server.url("/api/v1/admin/devices/netnew/network-diagnostic"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"tool": "ping", "target": "-c 100"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_target.status(), 400);

    let missing_port = client
        .post(server.url("/api/v1/admin/devices/netnew/network-diagnostic"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"tool": "port_check", "target": "example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(missing_port.status(), 400);

    let ok: Value = client
        .post(server.url("/api/v1/admin/devices/netnew/network-diagnostic"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"tool": "port_check", "target": "example.com", "port": 443}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let job_id = ok["id"].as_str().unwrap();
    let pool = server.pool().await;
    let (job_type, options): (String, Value) = sqlx::query_as("SELECT type, options FROM jobs WHERE id = $1").bind(job_id).fetch_one(&pool).await.unwrap();
    assert_eq!(job_type, "NETWORK_DIAGNOSTIC");
    assert_eq!(options, json!({"tool": "port_check", "target": "example.com", "port": 443}));
}

#[tokio::test]
async fn wake_on_lan_requires_mac_online_relay_and_agent_version() {
    let server = TestServer::start().await;
    seed_fixture_devices(&server).await;
    let (client, csrf) = setup_admin(&server).await;

    let no_mac = client
        .post(server.url("/api/v1/admin/devices/netnomac/wake"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"relay_device_id": "netnew"}))
        .send()
        .await
        .unwrap();
    assert_eq!(no_mac.status(), 409, "{}", no_mac.text().await.unwrap());
    let no_mac_body: Value = no_mac.json().await.unwrap();
    assert!(no_mac_body["detail"].as_str().unwrap().contains("MAC"));

    let offline_relay = client
        .post(server.url("/api/v1/admin/devices/netnomac/wake"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"relay_device_id": "netoffline"}))
        .send()
        .await
        .unwrap();
    assert_eq!(offline_relay.status(), 409);

    let old_relay = client
        .post(server.url("/api/v1/admin/devices/netoffline/wake"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"relay_device_id": "dev"}))
        .send()
        .await
        .unwrap();
    assert_eq!(old_relay.status(), 409);

    let self_relay = client
        .post(server.url("/api/v1/admin/devices/netoffline/wake"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"relay_device_id": "netoffline"}))
        .send()
        .await
        .unwrap();
    assert_eq!(self_relay.status(), 400);

    let ok: Value = client
        .post(server.url("/api/v1/admin/devices/netoffline/wake"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"relay_device_id": "netnew"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ok["mac"], "11:22:33:44:55:66");
    let job_id = ok["id"].as_str().unwrap();
    let pool = server.pool().await;
    let (device_id, job_type, options): (String, String, Value) =
        sqlx::query_as("SELECT device_id, type, options FROM jobs WHERE id = $1").bind(job_id).fetch_one(&pool).await.unwrap();
    assert_eq!(device_id, "netnew");
    assert_eq!(job_type, "WAKE_ON_LAN");
    assert_eq!(options, json!({"mac": "11:22:33:44:55:66", "target_device_id": "netoffline"}));
}
