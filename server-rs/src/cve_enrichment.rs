//! Enriches vulnerability findings that a scanner reported with no severity
//! of its own (notably debsecan/Debian Security Tracker, which doesn't score
//! every entry with an "urgency" level) by looking up the CVE's real,
//! published CVSS-based severity from the National Vulnerability Database.
//! Runs fire-and-forget after report_vulnerabilities commits the agent's
//! raw scan (devices.rs's report_vulnerabilities) -- NVD's public API is
//! rate-limited (5 req/30s with no key, 50/30s with FLEETVIEW_NVD_API_KEY
//! set) and can be slow or unreachable, so this must never add latency to
//! the agent's own report request.
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{PgPool, Row};
use std::time::Duration;

const CACHE_TTL_DAYS: i64 = 90;
const MAX_LOOKUPS_PER_PASS: usize = 25;

pub async fn enrich_device_vulnerabilities(pool: PgPool, device_id: String, scanned_at: DateTime<Utc>) {
    let Some(mut vulnerabilities) = current_vulnerabilities(&pool, &device_id, scanned_at).await else {
        return;
    };
    let api_key = std::env::var("FLEETVIEW_NVD_API_KEY").ok().filter(|k| !k.is_empty());
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("FleetView/1.0 (+https://github.com/MotherTruck/Fleetview)")
        .build()
    else {
        return;
    };
    // NVD's public rate limit is 5 requests/30s (50/30s with an API key) --
    // spacing calls out is simpler and more robust than a token-bucket for
    // the handful of lookups one scan report typically needs.
    let delay = if api_key.is_some() { Duration::from_millis(700) } else { Duration::from_millis(6500) };

    let mut changed = false;
    let mut lookups = 0usize;
    for finding in vulnerabilities.iter_mut() {
        if lookups >= MAX_LOOKUPS_PER_PASS {
            break;
        }
        let Some(obj) = finding.as_object() else { continue };
        let severity = obj.get("severity").and_then(Value::as_str).unwrap_or("UNKNOWN");
        if !severity.is_empty() && severity != "UNKNOWN" {
            continue;
        }
        let Some(cve_id) = obj.get("vulnerability_id").and_then(Value::as_str).map(str::to_string) else {
            continue;
        };
        if !looks_like_cve_id(&cve_id) {
            continue;
        }

        if lookups > 0 {
            tokio::time::sleep(delay).await;
        }
        lookups += 1;

        let Some((new_severity, score)) = lookup_severity(&client, &pool, &cve_id, api_key.as_deref()).await else {
            continue;
        };
        if let Some(map) = finding.as_object_mut() {
            map.insert("severity".to_string(), Value::String(new_severity));
            map.insert("severity_source".to_string(), Value::String("nvd".to_string()));
            if let Some(score) = score {
                map.insert("cvss_score".to_string(), serde_json::json!(score));
            }
        }
        changed = true;
    }

    if changed {
        write_back(&pool, &device_id, scanned_at, &vulnerabilities).await;
    }
}

/// Reads the device's just-committed `_security.vulnerabilities` back out,
/// confirming its `scanned_at` still matches the report we were spawned
/// for -- if a newer scan has already landed by the time this runs, there's
/// nothing for this pass to usefully enrich.
async fn current_vulnerabilities(pool: &PgPool, device_id: &str, scanned_at: DateTime<Utc>) -> Option<Vec<Value>> {
    let row = sqlx::query("SELECT inventory FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await
        .ok()??;
    let inventory: Value = row.try_get("inventory").ok()?;
    let security = inventory.get("_security")?;
    let stored_scanned_at: DateTime<Utc> = security.get("scanned_at")?.as_str()?.parse().ok()?;
    if stored_scanned_at != scanned_at {
        return None;
    }
    Some(security.get("vulnerabilities")?.as_array()?.clone())
}

/// Re-reads the device row once more right before writing (the lookups
/// above can take tens of seconds) and only writes if scanned_at still
/// matches, so a scan that completed while this pass was running is never
/// clobbered with stale enrichment results.
async fn write_back(pool: &PgPool, device_id: &str, scanned_at: DateTime<Utc>, vulnerabilities: &[Value]) {
    let Ok(Some(row)) = sqlx::query("SELECT inventory FROM devices WHERE id = $1")
        .bind(device_id)
        .fetch_optional(pool)
        .await
    else {
        return;
    };
    let Ok(mut inventory) = row.try_get::<Value, _>("inventory") else { return };
    let Some(inventory_obj) = inventory.as_object_mut() else { return };
    let Some(security) = inventory_obj.get_mut("_security").and_then(Value::as_object_mut) else { return };
    let still_current = security
        .get("scanned_at")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<DateTime<Utc>>().ok())
        == Some(scanned_at);
    if !still_current {
        return;
    }
    security.insert("vulnerabilities".to_string(), serde_json::json!(vulnerabilities));
    let _ = sqlx::query("UPDATE devices SET inventory = $1 WHERE id = $2")
        .bind(&inventory)
        .bind(device_id)
        .execute(pool)
        .await;
}

async fn lookup_severity(
    client: &reqwest::Client,
    pool: &PgPool,
    cve_id: &str,
    api_key: Option<&str>,
) -> Option<(String, Option<f64>)> {
    if let Ok(Some(row)) = sqlx::query("SELECT severity, cvss_score, fetched_at FROM cve_cache WHERE cve_id = $1")
        .bind(cve_id)
        .fetch_optional(pool)
        .await
    {
        let fetched_at: DateTime<Utc> = row.try_get("fetched_at").ok()?;
        if Utc::now() - fetched_at < chrono::Duration::days(CACHE_TTL_DAYS) {
            return Some((row.try_get("severity").ok()?, row.try_get("cvss_score").ok()));
        }
    }

    let mut request = client
        .get("https://services.nvd.nist.gov/rest/json/cves/2.0")
        .query(&[("cveId", cve_id)]);
    if let Some(key) = api_key {
        request = request.header("apiKey", key);
    }
    let response = match request.send().await {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            tracing::warn!("NVD lookup for {cve_id} returned {}", response.status());
            return None;
        }
        Err(error) => {
            tracing::warn!("NVD lookup for {cve_id} failed: {error}");
            return None;
        }
    };
    let body: Value = response.json().await.ok()?;
    let (severity, score) = parse_nvd_response(&body)?;

    let _ = sqlx::query(
        "INSERT INTO cve_cache (cve_id, severity, cvss_score, fetched_at) VALUES ($1,$2,$3,$4) \
         ON CONFLICT (cve_id) DO UPDATE SET severity = EXCLUDED.severity, cvss_score = EXCLUDED.cvss_score, fetched_at = EXCLUDED.fetched_at",
    )
    .bind(cve_id)
    .bind(&severity)
    .bind(score)
    .bind(Utc::now())
    .execute(pool)
    .await;

    Some((severity, score))
}

/// NVD API 2.0's per-CVE response nests metrics under one of
/// cvssMetricV31/V30/V2 (preferring the newest available). v3.x carries
/// baseSeverity inside cvssData; v2's baseSeverity (NVD's own bucketing of
/// the v2 score, since the v2 spec itself has no severity field) sits
/// alongside cvssData instead -- the two-step lookup below covers both
/// shapes with the same code.
fn parse_nvd_response(body: &Value) -> Option<(String, Option<f64>)> {
    let cve = body.get("vulnerabilities")?.as_array()?.first()?.get("cve")?;
    let metrics = cve.get("metrics")?;
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
        let Some(entry) = metrics.get(key).and_then(Value::as_array).and_then(|arr| arr.first()) else {
            continue;
        };
        let cvss_data = entry.get("cvssData");
        let severity = entry
            .get("baseSeverity")
            .and_then(Value::as_str)
            .or_else(|| cvss_data.and_then(|d| d.get("baseSeverity")).and_then(Value::as_str));
        if let Some(severity) = severity {
            let score = cvss_data.and_then(|d| d.get("baseScore")).and_then(Value::as_f64);
            return Some((severity.to_uppercase(), score));
        }
    }
    None
}

fn looks_like_cve_id(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("CVE-") else { return false };
    let Some((year, sequence)) = rest.split_once('-') else { return false };
    year.len() == 4
        && year.chars().all(|c| c.is_ascii_digit())
        && !sequence.is_empty()
        && sequence.chars().all(|c| c.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cve_id_pattern_accepts_real_ids_and_rejects_everything_else() {
        assert!(looks_like_cve_id("CVE-2024-1234"));
        assert!(looks_like_cve_id("CVE-2024-123456"));
        assert!(!looks_like_cve_id("TEMP-0123456-abcdef"));
        assert!(!looks_like_cve_id("CVE-24-1234"));
        assert!(!looks_like_cve_id("CVE-2024-"));
        assert!(!looks_like_cve_id("CVE-2024"));
        assert!(!looks_like_cve_id(""));
    }

    #[test]
    fn parses_v31_metrics_preferring_them_over_v2() {
        let body = serde_json::json!({
            "vulnerabilities": [{
                "cve": {
                    "metrics": {
                        "cvssMetricV31": [{ "cvssData": { "baseScore": 9.8, "baseSeverity": "CRITICAL" } }],
                        "cvssMetricV2": [{ "baseSeverity": "HIGH", "cvssData": { "baseScore": 7.5 } }]
                    }
                }
            }]
        });
        let (severity, score) = parse_nvd_response(&body).unwrap();
        assert_eq!(severity, "CRITICAL");
        assert_eq!(score, Some(9.8));
    }

    #[test]
    fn falls_back_to_v2_baseseverity_sitting_outside_cvssdata() {
        let body = serde_json::json!({
            "vulnerabilities": [{
                "cve": { "metrics": { "cvssMetricV2": [{ "baseSeverity": "MEDIUM", "cvssData": { "baseScore": 5.0 } }] } }
            }]
        });
        let (severity, score) = parse_nvd_response(&body).unwrap();
        assert_eq!(severity, "MEDIUM");
        assert_eq!(score, Some(5.0));
    }

    #[test]
    fn returns_none_when_no_metrics_present() {
        let body = serde_json::json!({ "vulnerabilities": [{ "cve": { "metrics": {} } }] });
        assert!(parse_nvd_response(&body).is_none());
        assert!(parse_nvd_response(&serde_json::json!({})).is_none());
    }
}
