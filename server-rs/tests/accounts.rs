//! Black-box port of server/tests/test_accounts.py against the real Rust
//! server + real Postgres (see tests/common/mod.rs).
mod common;
use common::{fv_header, TestServer, ADMIN_TOKEN, PASSWORD};
use serde_json::{json, Value};

const NEW_PASSWORD: &str = "a-new-long-password-456";

async fn setup_admin(server: &TestServer, client: &reqwest::Client) -> Value {
    let response = client
        .post(server.url("/api/v1/auth/setup"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"admin_token": ADMIN_TOKEN, "username": "Owner", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    response.json().await.unwrap()
}

fn csrf(setup_response: &Value) -> String {
    setup_response["csrf_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn bootstrap_and_legacy_token_cutoff() {
    let server = TestServer::start().await;
    let client = server.client();

    let status: Value = client.get(server.url("/api/v1/auth/status")).send().await.unwrap().json().await.unwrap();
    assert_eq!(status["setup_required"], true);

    let bad = client
        .post(server.url("/api/v1/auth/setup"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "owner", "password": PASSWORD, "admin_token": "wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad.status(), 401);

    let setup_body = setup_admin(&server, &client).await;
    let cookie_header = client
        .get(server.url("/api/v1/auth/status"))
        .send()
        .await
        .unwrap();
    let _ = cookie_header; // cookie jar already captured the Set-Cookie by reqwest

    let status: Value = client.get(server.url("/api/v1/auth/status")).send().await.unwrap().json().await.unwrap();
    assert_eq!(status["setup_required"], false);

    let me: Value = client.get(server.url("/api/v1/auth/me")).send().await.unwrap().json().await.unwrap();
    assert_eq!(me["user"]["username"], "owner");

    let dup = client
        .post(server.url("/api/v1/auth/setup"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "other", "password": PASSWORD, "admin_token": ADMIN_TOKEN}))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 409);
    let _ = setup_body;

    // Legacy X-Admin-Token bootstrap is dead once setup is complete.
    let other = server.client();
    let legacy = other
        .get(server.url("/api/v1/admin/devices"))
        .header("X-Admin-Token", ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(legacy.status(), 401);

    // Agent auth (unrelated to browser session bootstrap) still works for a
    // device that was never seeded here -- expect 401 (unknown device), not
    // some bootstrap-related failure mode.
    let heartbeat = other
        .post(server.url("/api/v1/agent/heartbeat"))
        .header("X-Device-ID", "endpoint")
        .header("Authorization", "Bearer endpoint-secret")
        .send()
        .await
        .unwrap();
    assert_eq!(heartbeat.status(), 401);
}

#[tokio::test]
async fn csrf_origin_cookie_and_password_secrecy() {
    let server = TestServer::start().await;

    let outsider = server.client();
    let payload = json!({"username": "owner", "password": PASSWORD, "admin_token": ADMIN_TOKEN});
    let missing_header = outsider.post(server.url("/api/v1/auth/setup")).json(&payload).send().await.unwrap();
    assert_eq!(missing_header.status(), 403);
    let cross_site = outsider
        .post(server.url("/api/v1/auth/setup"))
        .header(fv_header().0, fv_header().1)
        .header("Origin", "https://evil.example")
        .json(&payload)
        .send()
        .await
        .unwrap();
    assert_eq!(cross_site.status(), 403);

    let client = server.client();
    let setup_body = setup_admin(&server, &client).await;
    let _ = setup_body;

    // No CSRF token attached -> every state-changing request is rejected.
    let no_csrf = client
        .post(server.url("/api/v1/admin/users"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "test", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(no_csrf.status(), 403);
    let logout_no_csrf = client.post(server.url("/api/v1/auth/logout")).header(fv_header().0, fv_header().1).send().await.unwrap();
    assert_eq!(logout_no_csrf.status(), 403);

    // A failed login must never echo the submitted password back.
    let bad_login = client
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "bad space", "password": "secret-rejected"}))
        .send()
        .await
        .unwrap();
    let body = bad_login.text().await.unwrap();
    assert!(!body.contains("secret-rejected"));
}

#[tokio::test]
async fn viewer_and_operator_permissions_enforced_on_api() {
    let server = TestServer::start().await;
    server.seed_device("endpoint", "existing", "unused-hash").await;
    let owner = server.client();
    let setup_body = setup_admin(&server, &owner).await;
    let csrf_token = csrf(&setup_body);

    for role in ["viewer", "operator"] {
        let created = owner
            .post(server.url("/api/v1/admin/users"))
            .header(fv_header().0, fv_header().1)
            .header("X-CSRF-Token", &csrf_token)
            .json(&json!({"username": role, "password": PASSWORD, "role": role}))
            .send()
            .await
            .unwrap();
        assert_eq!(created.status(), 201, "creating {role}");

        let temp = server.client();
        let login = temp
            .post(server.url("/api/v1/auth/login"))
            .header(fv_header().0, fv_header().1)
            .json(&json!({"username": role, "password": PASSWORD}))
            .send()
            .await
            .unwrap();
        assert_eq!(login.status(), 200);
        let login_body: Value = login.json().await.unwrap();
        let temp_csrf = csrf(&login_body);

        // Temporary (must-change-password) sessions can't reach admin APIs.
        let denied = temp.get(server.url("/api/v1/admin/devices")).send().await.unwrap();
        assert_eq!(denied.status(), 403);

        let changed = temp
            .post(server.url("/api/v1/auth/password"))
            .header(fv_header().0, fv_header().1)
            .header("X-CSRF-Token", &temp_csrf)
            .json(&json!({"current_password": PASSWORD, "new_password": NEW_PASSWORD}))
            .send()
            .await
            .unwrap();
        assert_eq!(changed.status(), 204);
        // Changing password invalidates the session that changed it.
        let stale = temp.get(server.url("/api/v1/auth/me")).send().await.unwrap();
        assert_eq!(stale.status(), 401);

        let signed_in = server.client();
        let login2 = signed_in
            .post(server.url("/api/v1/auth/login"))
            .header(fv_header().0, fv_header().1)
            .json(&json!({"username": role, "password": NEW_PASSWORD}))
            .send()
            .await
            .unwrap();
        assert_eq!(login2.status(), 200);

        for url in ["/api/v1/admin/devices", "/api/v1/admin/packages", "/api/v1/admin/reports/history", "/api/v1/admin/jobs"] {
            let response = signed_in.get(server.url(url)).send().await.unwrap();
            assert_eq!(response.status(), 200, "{role} GET {url}");
        }
        for url in ["/api/v1/admin/users", "/api/v1/admin/enrollment-tokens", "/api/v1/admin/users/audit/recent"] {
            let response = signed_in.get(server.url(url)).send().await.unwrap();
            assert_eq!(response.status(), 403, "{role} GET {url}");
        }

        let login2_body: Value = login2.json().await.unwrap();
        let signed_in_csrf = csrf(&login2_body);
        let delete_device = signed_in
            .delete(server.url("/api/v1/admin/devices/endpoint"))
            .header("X-CSRF-Token", &signed_in_csrf)
            .send()
            .await
            .unwrap();
        assert_eq!(delete_device.status(), 403);

        let put_settings = signed_in
            .put(server.url("/api/v1/admin/settings"))
            .header("X-CSRF-Token", &signed_in_csrf)
            .json(&json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(put_settings.status(), 403);

        let create_job = signed_in
            .post(server.url("/api/v1/admin/devices/endpoint/jobs"))
            .header("X-CSRF-Token", &signed_in_csrf)
            .json(&json!({"type": "SCAN_DEVICE"}))
            .send()
            .await
            .unwrap();
        let expected = if role == "operator" { 201 } else { 403 };
        assert_eq!(create_job.status(), expected, "{role} create job");
    }
}

#[tokio::test]
async fn disable_reset_and_last_admin() {
    let server = TestServer::start().await;
    let owner_client = server.client();
    let setup_body = setup_admin(&server, &owner_client).await;
    let csrf_token = csrf(&setup_body);
    let owner_id = setup_body["user"]["id"].as_str().unwrap().to_string();

    // Can't demote or disable the only admin.
    let demote = owner_client
        .put(server.url(&format!("/api/v1/admin/users/{owner_id}")))
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"role": "viewer", "active": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(demote.status(), 409);
    let disable = owner_client
        .put(server.url(&format!("/api/v1/admin/users/{owner_id}")))
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"role": "admin", "active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(disable.status(), 409);

    let created = owner_client
        .post(server.url("/api/v1/admin/users"))
        .header(fv_header().0, fv_header().1)
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"username": "viewer", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    let created_body: Value = created.json().await.unwrap();
    let user_id = created_body["id"].as_str().unwrap().to_string();

    let other = server.client();
    let login = other
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "viewer", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(login.status(), 200);

    // Admin disables that user while they're signed in.
    let disable_other = owner_client
        .put(server.url(&format!("/api/v1/admin/users/{user_id}")))
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"role": "operator", "active": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(disable_other.status(), 200);

    let stale = other.get(server.url("/api/v1/auth/me")).send().await.unwrap();
    assert_eq!(stale.status(), 401);
    let relogin = other
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "viewer", "password": PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(relogin.status(), 401);

    // Admin resets the disabled user's password, forcing a temporary one.
    let reset = owner_client
        .put(server.url(&format!("/api/v1/admin/users/{user_id}")))
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"role": "viewer", "active": true, "password": NEW_PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status(), 200);

    let reset_client = server.client();
    let relogin2 = reset_client
        .post(server.url("/api/v1/auth/login"))
        .header(fv_header().0, fv_header().1)
        .json(&json!({"username": "viewer", "password": NEW_PASSWORD}))
        .send()
        .await
        .unwrap();
    assert_eq!(relogin2.status(), 200);
    let me: Value = reset_client.get(server.url("/api/v1/auth/me")).send().await.unwrap().json().await.unwrap();
    assert_eq!(me["user"]["must_change_password"], true);

    let audit: Value = owner_client.get(server.url("/api/v1/admin/users/audit/recent")).send().await.unwrap().json().await.unwrap();
    assert!(audit.as_array().map(|a| !a.is_empty()).unwrap_or(false));
}

#[tokio::test]
async fn duplicate_username_and_role_validation() {
    let server = TestServer::start().await;
    let client = server.client();
    let setup_body = setup_admin(&server, &client).await;
    let csrf_token = csrf(&setup_body);

    let created = client
        .post(server.url("/api/v1/admin/users"))
        .header(fv_header().0, fv_header().1)
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"username": "viewer", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    // Username collision is case-insensitive.
    let dup = client
        .post(server.url("/api/v1/admin/users"))
        .header(fv_header().0, fv_header().1)
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"username": "VIEWER", "password": PASSWORD, "role": "admin"}))
        .send()
        .await
        .unwrap();
    assert_eq!(dup.status(), 409);

    let bad_role = client
        .post(server.url("/api/v1/admin/users"))
        .header(fv_header().0, fv_header().1)
        .header("X-CSRF-Token", &csrf_token)
        .json(&json!({"username": "someone", "password": PASSWORD, "role": "superuser"}))
        .send()
        .await
        .unwrap();
    assert_eq!(bad_role.status(), 400, "invalid role should be rejected (Rust returns 400 for a bad-request body shape, matching bad_request semantics; Python's Pydantic returns 422 for the same case)");
}
