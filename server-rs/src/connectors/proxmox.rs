//! Outbound client for the Proxmox VE REST API.
//!
//! Auth is an API token (Datacenter -> Permissions -> API Tokens in the
//! Proxmox UI), sent as the header Proxmox's own docs specify:
//! `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`. Every
//! Proxmox API response is wrapped in a top-level "data" key.
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::time::Duration;

pub const REQUIRED_CREDENTIAL_FIELDS: &[&str] = &["token_id", "token_secret"];

pub async fn fetch_inventory(base_url: &str, credentials: &HashMap<String, String>, verify_tls: bool) -> Result<Value, String> {
    let token_id = credentials.get("token_id").cloned().unwrap_or_default();
    let token_secret = credentials.get("token_secret").cloned().unwrap_or_default();
    let base = base_url.trim_end_matches('/');

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(Duration::from_secs(10))
        .default_headers({
            let mut headers = reqwest::header::HeaderMap::new();
            let value = format!("PVEAPIToken={token_id}={token_secret}");
            if let Ok(header_value) = reqwest::header::HeaderValue::from_str(&value) {
                headers.insert(reqwest::header::AUTHORIZATION, header_value);
            }
            headers
        })
        .build()
        .map_err(|error| format!("Could not build HTTP client: {error}"))?;

    let nodes_response = client
        .get(format!("{base}/api2/json/nodes"))
        .send()
        .await
        .map_err(|error| format!("Could not reach Proxmox at {base}: {error}"))?;
    let status = nodes_response.status();
    if !status.is_success() {
        let reason = if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            "check the API token and that it has PVEAuditor (or greater) permission".to_string()
        } else {
            format!("HTTP {}", status.as_u16())
        };
        return Err(format!("Proxmox API returned {}: {}", status.as_u16(), reason));
    }
    let nodes_body: Value = nodes_response
        .json()
        .await
        .map_err(|error| format!("Could not reach Proxmox at {base}: {error}"))?;
    let nodes = nodes_body.get("data").cloned().unwrap_or(Value::Array(vec![]));
    let Some(node_list) = nodes.as_array() else {
        return Err("Unexpected response from Proxmox's /nodes endpoint".to_string());
    };

    let mut vms = Vec::new();
    let mut containers = Vec::new();
    for node in node_list {
        let Some(node_name) = node.get("node").and_then(Value::as_str) else {
            continue;
        };
        for (guest_type, bucket) in [("qemu", &mut vms), ("lxc", &mut containers)] {
            let response = match client.get(format!("{base}/api2/json/nodes/{node_name}/{guest_type}")).send().await {
                Ok(response) if response.status().is_success() => response,
                // One node being slow/unreachable shouldn't blank the rest
                // of a healthy cluster's inventory.
                _ => continue,
            };
            let Ok(body) = response.json::<Value>().await else {
                continue;
            };
            if let Some(guests) = body.get("data").and_then(Value::as_array) {
                for guest in guests {
                    if let Some(obj) = guest.as_object() {
                        let mut entry = obj.clone();
                        entry.insert("node".to_string(), Value::String(node_name.to_string()));
                        bucket.push(Value::Object(entry));
                    }
                }
            }
        }
    }

    Ok(json!({ "nodes": node_list, "vms": vms, "containers": containers }))
}
