-- Per-container CPU/memory samples, alongside the existing device-level
-- metric_samples. Populated from the same periodic metrics report's
-- top_consumers field (already gathered every cycle for the live Top
-- Consumers snapshot) -- this just also keeps the container entries
-- instead of discarding them, so the dashboard can chart Docker CPU/
-- memory usage over time the same way it already does for the host.
CREATE TABLE container_metric_samples (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    container_name VARCHAR(255) NOT NULL,
    cpu_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_bytes BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX ix_container_metric_samples_device_id ON container_metric_samples(device_id);
CREATE INDEX ix_container_metric_samples_recorded_at ON container_metric_samples(recorded_at);
CREATE INDEX ix_container_metric_samples_device_recorded ON container_metric_samples(device_id, recorded_at);
