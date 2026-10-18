//! Exercises devices.rs's job-lease recovery (reap_stale_jobs/
//! reap_stale_jobs_loop): a job an agent claimed and then never reported
//! back on (crash, lost completion POST, device never came back online)
//! must not sit "running" forever -- it should flip to outcome_unknown
//! once its lease expires, and still accept a late completion report if
//! the agent does eventually check back in.
mod common;
use common::{fv_header, TestServer, ADMIN_TOKEN, PASSWORD};
use serde_json::{json, Value};
use sqlx::Row;

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

#[tokio::test]
async fn stale_running_job_is_reaped_to_outcome_unknown_and_unblocks_a_new_equivalent_job() {
    let server = TestServer::start_with_env(&[
        ("FLEETVIEW_JOB_LEASE_SECONDS", "1".to_string()),
        ("FLEETVIEW_JOB_REAP_INTERVAL_SECONDS", "1".to_string()),
    ])
    .await;
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(b"agent-test"))
    };
    server.seed_device_full("one", "stale-job-host", "linux", "apt", "0.20.0", &token_hash, json!([]), json!({}), None).await;
    let (client, csrf) = setup_admin(&server).await;

    let created = client
        .post(server.url("/api/v1/admin/devices/one/jobs"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"type": "SCAN_DEVICE", "options": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201, "{}", created.text().await.unwrap());
    let job: Value = created.json().await.unwrap();
    let job_id = job["id"].as_str().unwrap().to_string();

    // The agent claims it -- status becomes running, claimed_at is set.
    let agent = server.client();
    let next = agent
        .get(server.url("/api/v1/agent/jobs/next"))
        .header("X-Device-Id", "one")
        .header("Authorization", "Bearer agent-test")
        .send()
        .await
        .unwrap();
    assert_eq!(next.status(), 200);
    let claimed: Value = next.json().await.unwrap();
    assert_eq!(claimed["id"].as_str().unwrap(), job_id);
    assert_eq!(claimed["status"], "running");

    // Simulate the agent having claimed this a while ago (crashed, or its
    // completion POST never arrived) by backdating claimed_at well past
    // the 1-second lease this test configured, rather than waiting out a
    // real lease window.
    let pool = server.pool().await;
    sqlx::query("UPDATE jobs SET claimed_at = now() - interval '10 seconds' WHERE id = $1")
        .bind(&job_id)
        .execute(&pool)
        .await
        .unwrap();

    // Give the 1-second reap loop a couple of ticks to catch it.
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;

    let row = sqlx::query("SELECT status, error FROM jobs WHERE id = $1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let status: String = row.get("status");
    let error: Option<String> = row.get("error");
    assert_eq!(status, "outcome_unknown");
    assert!(error.unwrap().contains("did not report a result"));

    // The stale job no longer counts as "in flight", so a fresh equivalent
    // job can be queued -- this is the actual bug the review flagged: a
    // stuck job silently blocking every future equivalent one.
    let requeued = client
        .post(server.url("/api/v1/admin/devices/one/jobs"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"type": "SCAN_DEVICE", "options": {}}))
        .send()
        .await
        .unwrap();
    assert_eq!(requeued.status(), 201, "{}", requeued.text().await.unwrap());
    let requeued_job: Value = requeued.json().await.unwrap();
    assert_ne!(requeued_job["id"].as_str().unwrap(), job_id, "a distinct job should have been created");

    // A late completion report for the reaped job is still accepted and
    // overwrites outcome_unknown with the agent's real, if tardy, answer.
    let late = agent
        .post(server.url(&format!("/api/v1/agent/jobs/{job_id}/result")))
        .header("X-Device-Id", "one")
        .header("Authorization", "Bearer agent-test")
        .json(&json!({"status": "succeeded", "exit_code": 0, "output": "finished after all"}))
        .send()
        .await
        .unwrap();
    assert_eq!(late.status(), 204, "{}", late.text().await.unwrap());
    let final_row = sqlx::query("SELECT status, output FROM jobs WHERE id = $1")
        .bind(&job_id)
        .fetch_one(&pool)
        .await
        .unwrap();
    let final_status: String = final_row.get("status");
    let final_output: Option<String> = final_row.get("output");
    assert_eq!(final_status, "succeeded");
    assert_eq!(final_output.unwrap(), "finished after all");
}

#[tokio::test]
async fn completing_an_already_terminal_job_is_rejected() {
    let server = TestServer::start().await;
    let token_hash = {
        use sha2::{Digest, Sha256};
        hex::encode(Sha256::digest(b"agent-test"))
    };
    server.seed_device_full("one", "terminal-job-host", "linux", "apt", "0.20.0", &token_hash, json!([]), json!({}), None).await;
    let (client, csrf) = setup_admin(&server).await;

    let created = client
        .post(server.url("/api/v1/admin/devices/one/jobs"))
        .header("X-CSRF-Token", &csrf)
        .json(&json!({"type": "SCAN_DEVICE", "options": {}}))
        .send()
        .await
        .unwrap();
    let job: Value = created.json().await.unwrap();
    let job_id = job["id"].as_str().unwrap().to_string();

    let agent = server.client();
    agent
        .get(server.url("/api/v1/agent/jobs/next"))
        .header("X-Device-Id", "one")
        .header("Authorization", "Bearer agent-test")
        .send()
        .await
        .unwrap();
    let first = agent
        .post(server.url(&format!("/api/v1/agent/jobs/{job_id}/result")))
        .header("X-Device-Id", "one")
        .header("Authorization", "Bearer agent-test")
        .json(&json!({"status": "succeeded", "exit_code": 0, "output": "ok"}))
        .send()
        .await
        .unwrap();
    assert_eq!(first.status(), 204);

    // A second report for an already-succeeded job is a replay/duplicate,
    // not a late-arriving truth -- rejected, unlike the outcome_unknown case.
    let second = agent
        .post(server.url(&format!("/api/v1/agent/jobs/{job_id}/result")))
        .header("X-Device-Id", "one")
        .header("Authorization", "Bearer agent-test")
        .json(&json!({"status": "failed", "exit_code": 1, "error": "replay"}))
        .send()
        .await
        .unwrap();
    assert_eq!(second.status(), 409);
}
