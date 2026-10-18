-- Outbound notification channels (server-rs/src/alerting.rs): a webhook
-- URL, optionally formatted as a Slack-compatible {"text": "..."} payload
-- instead of FleetView's own generic JSON shape -- Slack, Discord (via its
-- Slack-compatible webhook mode), and Mattermost all accept that same
-- {"text": ...} shape, which covers most self-hosted chat notification
-- needs without a bespoke integration per vendor.
CREATE TABLE notification_channels (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    url TEXT NOT NULL,
    format VARCHAR(20) NOT NULL DEFAULT 'generic',
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- A condition to watch. `metric` and `threshold_value` are only
-- meaningful for kind='resource_threshold' (metric is 'cpu'/'memory'/
-- 'disk', threshold_value a percent); threshold_value alone is reused for
-- kind='device_offline' (minutes since last_seen). tag_filter, when set,
-- scopes the rule to devices carrying that tag (see devices._tags);
-- null/empty means every device.
CREATE TABLE alert_rules (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    kind VARCHAR(30) NOT NULL,
    metric VARCHAR(10) NULL,
    threshold_value DOUBLE PRECISION NULL,
    tag_filter VARCHAR(64) NULL,
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per currently-firing (rule, device) pair -- the evaluation loop
-- (alerting::evaluate_loop) inserts one the moment a level-triggered
-- condition (device_offline, resource_threshold, vulnerability_found)
-- starts matching and deletes it the moment it stops, so a rule notifies
-- once on the way up and once on the way down rather than every tick
-- while the condition persists.
CREATE TABLE alert_firings (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(36) NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    first_fired_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(rule_id, device_id)
);
CREATE INDEX ix_alert_firings_rule_id ON alert_firings(rule_id);
