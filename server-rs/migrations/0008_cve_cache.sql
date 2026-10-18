-- Caches real severity/score data looked up from the National
-- Vulnerability Database (NVD) for CVEs that the OS-native scanner
-- (debsecan, in particular) reported with no severity of its own --
-- Debian's security tracker doesn't score every entry with an "urgency"
-- level, so a lot of findings would otherwise sit at UNKNOWN forever even
-- though the CVE itself has a real, published CVSS-based severity.
-- Shared across every device that happens to have the same CVE, and keyed
-- on the CVE ID alone so a lookup done for one device's scan benefits
-- every other device's next report too.
CREATE TABLE cve_cache (
    cve_id TEXT PRIMARY KEY,
    severity VARCHAR(20) NOT NULL,
    cvss_score DOUBLE PRECISION,
    fetched_at TIMESTAMPTZ NOT NULL
);
