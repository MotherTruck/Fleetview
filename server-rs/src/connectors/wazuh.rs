//! Read-only client for Wazuh's vulnerability findings.
//!
//! Since Wazuh 4.8 the manager no longer serves vulnerabilities over its REST
//! API (the old `GET /vulnerability/{agent_id}` was removed); the detector
//! writes them to the Wazuh *indexer* instead, in the
//! `wazuh-states-vulnerabilities-*` indices. So the Base URL here is the
//! indexer (default port 9200), authenticated with HTTP Basic. Only `_search`
//! is ever issued -- nothing is written to Wazuh. A dedicated indexer user
//! limited to `read` on `wazuh-states-vulnerabilities-*` is enough.
//!
//! This is written against the documented 4.8+ index mapping
//! (`agent.id`, `agent.name`, `package.name`, `package.version`,
//! `vulnerability.id`, `vulnerability.severity`, `vulnerability.score.base`,
//! `vulnerability.description`, `vulnerability.reference`) but has not been
//! run against a live Wazuh in this repo's test environment. If a field is
//! missing it is skipped rather than failing the sync. See
//! docs/INTEGRATIONS.md.
use reqwest::StatusCode;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::Duration;

pub const REQUIRED_CREDENTIAL_FIELDS: &[&str] = &["username", "password"];

const MAX_AGENTS: u32 = 500;
const FINDINGS_PER_AGENT: u32 = 20;
const MAX_DESCRIPTION_CHARS: usize = 300;
const SEVERITIES: [&str; 4] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

fn search_body() -> Value {
    json!({
        "size": 0,
        "track_total_hits": true,
        "aggs": {
            "agents": {
                "terms": { "field": "agent.name", "size": MAX_AGENTS },
                "aggs": {
                    "agent_id": { "terms": { "field": "agent.id", "size": 1 } },
                    "severity": { "terms": { "field": "vulnerability.severity", "size": 10 } },
                    "top": {
                        "top_hits": {
                            "size": FINDINGS_PER_AGENT,
                            "sort": [{ "vulnerability.score.base": { "order": "desc", "unmapped_type": "float" } }],
                            "_source": [
                                "vulnerability.id", "vulnerability.severity", "vulnerability.score.base",
                                "vulnerability.description", "vulnerability.reference",
                                "package.name", "package.version"
                            ]
                        }
                    }
                }
            }
        }
    })
}

fn text(value: Option<&Value>, max_chars: usize) -> String {
    value.and_then(Value::as_str).unwrap_or("").chars().take(max_chars).collect()
}

fn finding(source: &Value) -> Option<Value> {
    let id = text(source.pointer("/vulnerability/id"), 64);
    if id.is_empty() {
        return None;
    }
    Some(json!({
        "id": id,
        "severity": text(source.pointer("/vulnerability/severity"), 16).to_uppercase(),
        "score": source.pointer("/vulnerability/score/base").cloned().unwrap_or(Value::Null),
        "package": text(source.pointer("/package/name"), 255),
        "version": text(source.pointer("/package/version"), 128),
        "description": text(source.pointer("/vulnerability/description"), MAX_DESCRIPTION_CHARS),
        "reference": text(source.pointer("/vulnerability/reference"), 500),
    }))
}

/// Turns the aggregation response into FleetView's cached shape. Kept
/// separate from the HTTP call so it can be unit-tested.
fn summarize(body: &Value) -> Result<Value, String> {
    let buckets = body
        .pointer("/aggregations/agents/buckets")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            "Wazuh's response didn't have the expected shape (no agent aggregation). \
             This needs Wazuh 4.8+ -- see docs/INTEGRATIONS.md."
                .to_string()
        })?;
    let mut agents = Vec::new();
    let mut totals: Map<String, Value> = SEVERITIES.iter().map(|s| (s.to_string(), json!(0))).collect();
    for bucket in buckets {
        let Some(name) = bucket.get("key").and_then(Value::as_str) else { continue };
        let mut counts: Map<String, Value> = SEVERITIES.iter().map(|s| (s.to_string(), json!(0))).collect();
        for sev in bucket.pointer("/severity/buckets").and_then(Value::as_array).into_iter().flatten() {
            let label = sev.get("key").and_then(Value::as_str).unwrap_or("").to_uppercase();
            let count = sev.get("doc_count").and_then(Value::as_u64).unwrap_or(0);
            if let Some(slot) = counts.get_mut(&label) {
                *slot = json!(count);
                let total = totals.get(&label).and_then(Value::as_u64).unwrap_or(0);
                totals.insert(label, json!(total + count));
            }
        }
        let findings: Vec<Value> = bucket
            .pointer("/top/hits/hits")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|hit| hit.get("_source").and_then(finding))
            .collect();
        agents.push(json!({
            "name": name,
            "id": bucket.pointer("/agent_id/buckets/0/key").and_then(Value::as_str).unwrap_or(""),
            "total": bucket.get("doc_count").and_then(Value::as_u64).unwrap_or(0),
            "severity_counts": counts,
            "findings": findings,
            "findings_truncated": bucket.get("doc_count").and_then(Value::as_u64).unwrap_or(0) > findings.len() as u64,
        }));
    }
    Ok(json!({ "agents": agents, "severity_totals": totals }))
}

pub async fn fetch_inventory(base_url: &str, credentials: &HashMap<String, String>, verify_tls: bool) -> Result<Value, String> {
    let username = credentials.get("username").cloned().unwrap_or_default();
    let password = credentials.get("password").cloned().unwrap_or_default();
    let base = base_url.trim_end_matches('/');
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(!verify_tls)
        .timeout(Duration::from_secs(20))
        .build()
        .map_err(|error| format!("Could not build HTTP client: {error}"))?;

    let response = client
        .post(format!("{base}/wazuh-states-vulnerabilities-*/_search"))
        .basic_auth(username, Some(password))
        .json(&search_body())
        .send()
        .await
        .map_err(|error| format!("Could not reach the Wazuh indexer at {base}: {error}"))?;
    let status = response.status();
    if !status.is_success() {
        let reason = match status {
            StatusCode::UNAUTHORIZED => "check the indexer username/password".to_string(),
            StatusCode::FORBIDDEN => "the user needs read access to wazuh-states-vulnerabilities-*".to_string(),
            StatusCode::NOT_FOUND => "no vulnerability index found -- is the vulnerability detector enabled, on Wazuh 4.8+? \
                And is the Base URL the indexer (port 9200), not the manager API (port 55000)?"
                .to_string(),
            _ => format!("HTTP {}", status.as_u16()),
        };
        return Err(format!("Wazuh indexer returned {}: {}", status.as_u16(), reason));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|_| "The Wazuh indexer returned a non-JSON response".to_string())?;
    summarize(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summarizes_aggregation_into_per_agent_counts_and_findings() {
        let body = json!({"aggregations": {"agents": {"buckets": [{
            "key": "web01", "doc_count": 3,
            "agent_id": {"buckets": [{"key": "002"}]},
            "severity": {"buckets": [{"key": "Critical", "doc_count": 1}, {"key": "High", "doc_count": 2}]},
            "top": {"hits": {"hits": [
                {"_source": {"vulnerability": {"id": "CVE-2024-1", "severity": "Critical", "score": {"base": 9.8}},
                             "package": {"name": "openssl", "version": "3.0.1"}}},
                {"_source": {"package": {"name": "no-id"}}}
            ]}}
        }]}}});
        let out = summarize(&body).unwrap();
        let agent = &out["agents"][0];
        assert_eq!(agent["name"], "web01");
        assert_eq!(agent["id"], "002");
        assert_eq!(agent["severity_counts"]["CRITICAL"], 1);
        assert_eq!(agent["severity_counts"]["HIGH"], 2);
        assert_eq!(agent["findings"].as_array().unwrap().len(), 1);
        assert_eq!(agent["findings"][0]["severity"], "CRITICAL");
        assert_eq!(agent["findings_truncated"], true);
        assert_eq!(out["severity_totals"]["HIGH"], 2);
    }

    #[test]
    fn rejects_unexpected_shape_with_a_clear_error() {
        assert!(summarize(&json!({"hits": {}})).unwrap_err().contains("4.8"));
    }
}
