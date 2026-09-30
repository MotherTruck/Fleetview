//! Outbound client for the OPNsense REST API.
//!
//! Auth is HTTP Basic with an API key/secret pair (System -> Access -> Users,
//! generate an API key for the account), not a session cookie/CSRF-token pair
//! like the OPNsense web UI itself uses.
//!
//! OPNsense's DHCP lease endpoint has genuinely varied across versions and
//! DHCP backends (ISC dhcpd vs. the newer Kea plugin) in ways this project
//! cannot verify against a real instance in this environment -- this client
//! requests the endpoint documented for the Kea backend (the current default
//! on supported OPNsense releases) and fails with a clear, specific error if
//! the response shape doesn't match what's expected, rather than silently
//! showing wrong or empty data. See docs/INTEGRATIONS.md.
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

pub const REQUIRED_CREDENTIAL_FIELDS: &[&str] = &["api_key", "api_secret"];

fn client(verify_tls: bool, timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(timeout)
        .build()
        .map_err(|error| format!("Could not build HTTP client: {error}"))
}

async fn get(
    client: &reqwest::Client,
    base_url: &str,
    credentials: &HashMap<String, String>,
    path: &str,
) -> Result<Value, String> {
    let url = format!("{}{}", base_url.trim_end_matches('/'), path);
    let api_key = credentials.get("api_key").cloned().unwrap_or_default();
    let api_secret = credentials.get("api_secret").cloned().unwrap_or_default();
    let response = client
        .get(&url)
        .basic_auth(api_key, Some(api_secret))
        .send()
        .await
        .map_err(|error| format!("Could not reach OPNsense: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let reason = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            "check the API key/secret".to_string()
        } else {
            format!("HTTP {}", status.as_u16())
        };
        return Err(format!("OPNsense API returned {} for {}: {}", status.as_u16(), path, reason));
    }
    response
        .json::<Value>()
        .await
        .map_err(|_| format!("OPNsense returned a non-JSON response for {path}"))
}

/// Returns Err on failure; used by the "test connection" flow before an
/// integration is saved. /core/system/status is a lightweight, long-stable
/// endpoint that doesn't depend on which DHCP backend is configured, so
/// it's a good way to validate credentials/reachability independent of the
/// DHCP-lease-shape uncertainty described above.
#[allow(dead_code)]
pub async fn test_connection(base_url: &str, credentials: &HashMap<String, String>, verify_tls: bool) -> Result<(), String> {
    let client = client(verify_tls, Duration::from_secs(10))?;
    let payload = get(&client, base_url, credentials, "/api/core/system/status").await?;
    if !payload.is_object() {
        return Err("Unexpected response from OPNsense's system status endpoint".to_string());
    }
    Ok(())
}

fn or_field(obj: &serde_json::Map<String, Value>, primary: &str, secondary: &str) -> Value {
    let is_truthy = match obj.get(primary) {
        Some(Value::Null) | None => false,
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    };
    if is_truthy {
        obj.get(primary).cloned().unwrap()
    } else {
        obj.get(secondary).cloned().unwrap_or(Value::Null)
    }
}

async fn fetch_dhcp_leases(base_url: &str, credentials: &HashMap<String, String>, verify_tls: bool) -> Result<Vec<Value>, String> {
    let client = client(verify_tls, Duration::from_secs(10))?;
    let payload = get(&client, base_url, credentials, "/api/dhcpv4/leases/searchLease").await?;
    let rows = payload.get("rows").and_then(Value::as_array).ok_or_else(|| {
        "OPNsense's DHCP lease response didn't have the expected shape (no 'rows' list). \
         This endpoint varies between OPNsense versions/DHCP backends -- see docs/INTEGRATIONS.md."
            .to_string()
    })?;
    Ok(rows
        .iter()
        .filter_map(Value::as_object)
        .map(|row| {
            let hostname = row.get("hostname").and_then(Value::as_str).unwrap_or("");
            let state = row.get("state").and_then(Value::as_str).unwrap_or("");
            json!({
                "ip": or_field(row, "address", "ip"),
                "mac": or_field(row, "hwaddr", "mac"),
                "hostname": hostname,
                "state": state,
            })
        })
        .collect())
}

pub async fn fetch_inventory(base_url: &str, credentials: &HashMap<String, String>, verify_tls: bool) -> Result<Value, String> {
    let leases = fetch_dhcp_leases(base_url, credentials, verify_tls).await?;
    Ok(json!({ "dhcp_leases": leases }))
}
