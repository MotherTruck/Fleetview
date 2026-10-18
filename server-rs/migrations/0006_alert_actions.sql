-- Monitor-triggered automation: an alert rule can optionally run a saved
-- script against the device that tripped it, in addition to (not instead
-- of) notifying every channel -- e.g. a resource_threshold rule for disk
-- usage running a "clear package cache" script, or a job_failed rule
-- re-running a known-flaky step. ON DELETE SET NULL rather than CASCADE:
-- deleting the script a rule happens to reference should disarm that
-- one action, not silently delete the whole rule.
ALTER TABLE alert_rules ADD COLUMN action_script_id VARCHAR(36) NULL REFERENCES scripts(id) ON DELETE SET NULL;
