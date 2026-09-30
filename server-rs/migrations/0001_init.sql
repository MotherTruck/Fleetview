-- Mirrors server/app/models.py exactly (see that file for the
-- authoritative field-by-field commentary). Postgres only: the Python
-- server's SQLite path exists solely for its test suite's convenience,
-- production always runs Postgres (see docker-compose.yml), so the Rust
-- port targets Postgres exclusively and tests against a real instance.

CREATE TABLE auth_control (
    id INTEGER PRIMARY KEY
);

CREATE TABLE users (
    id VARCHAR(36) PRIMARY KEY,
    username VARCHAR(64) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
    active BOOLEAN NOT NULL DEFAULT true,
    must_change_password BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at TIMESTAMPTZ NULL
);

CREATE TABLE user_sessions (
    token_hash VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_user_sessions_user_id ON user_sessions(user_id);
CREATE INDEX ix_user_sessions_expires_at ON user_sessions(expires_at);

CREATE TABLE login_throttles (
    key VARCHAR(64) PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 0,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX ix_login_throttles_expires_at ON login_throttles(expires_at);

CREATE TABLE account_audit (
    id SERIAL PRIMARY KEY,
    actor VARCHAR(64) NOT NULL,
    action VARCHAR(50) NOT NULL,
    target VARCHAR(64) NOT NULL,
    details VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE devices (
    id VARCHAR(36) PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    display_name VARCHAR(255) NULL,
    platform VARCHAR(50) NOT NULL DEFAULT 'linux',
    os_name VARCHAR(255) NULL,
    os_version VARCHAR(255) NULL,
    architecture VARCHAR(50) NULL,
    package_manager VARCHAR(50) NULL,
    agent_version VARCHAR(50) NULL,
    agent_token_hash VARCHAR(64) NOT NULL,
    enrolled_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    inventory JSONB NOT NULL DEFAULT '{}',
    installed_packages JSONB NOT NULL DEFAULT '[]',
    available_updates JSONB NOT NULL DEFAULT '[]',
    update_count INTEGER NOT NULL DEFAULT 0,
    security_update_count INTEGER NOT NULL DEFAULT 0,
    last_scan_at TIMESTAMPTZ NULL
);
CREATE INDEX ix_devices_hostname ON devices(hostname);
CREATE INDEX ix_devices_last_seen ON devices(last_seen);

CREATE TABLE jobs (
    id VARCHAR(36) PRIMARY KEY,
    device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    options JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    claimed_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    exit_code INTEGER NULL,
    output TEXT NULL,
    error TEXT NULL
);
CREATE INDEX ix_jobs_device_id ON jobs(device_id);
CREATE INDEX ix_jobs_type ON jobs(type);
CREATE INDEX ix_jobs_status ON jobs(status);

CREATE TABLE enrollment_tokens (
    id VARCHAR(36) PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    label VARCHAR(255) NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    used_by_device_id VARCHAR(36) NULL REFERENCES devices(id) ON DELETE SET NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE TABLE metric_samples (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    cpu_percent DOUBLE PRECISION NOT NULL DEFAULT 0,
    memory_used_bytes BIGINT NOT NULL DEFAULT 0,
    memory_total_bytes BIGINT NOT NULL DEFAULT 0,
    swap_used_bytes BIGINT NOT NULL DEFAULT 0,
    swap_total_bytes BIGINT NOT NULL DEFAULT 0,
    disk_used_bytes BIGINT NOT NULL DEFAULT 0,
    disk_total_bytes BIGINT NOT NULL DEFAULT 0,
    load_1 DOUBLE PRECISION NOT NULL DEFAULT 0,
    load_5 DOUBLE PRECISION NOT NULL DEFAULT 0,
    load_15 DOUBLE PRECISION NOT NULL DEFAULT 0,
    network_receive_bps DOUBLE PRECISION NOT NULL DEFAULT 0,
    network_transmit_bps DOUBLE PRECISION NOT NULL DEFAULT 0,
    network_receive_bytes BIGINT NOT NULL DEFAULT 0,
    network_transmit_bytes BIGINT NOT NULL DEFAULT 0,
    process_count INTEGER NOT NULL DEFAULT 0,
    temperature_celsius DOUBLE PRECISION NULL,
    uptime_seconds INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX ix_metric_samples_device_id ON metric_samples(device_id);
CREATE INDEX ix_metric_samples_recorded_at ON metric_samples(recorded_at);

CREATE TABLE packages (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    version VARCHAR(100) NOT NULL DEFAULT '',
    category VARCHAR(100) NOT NULL DEFAULT '',
    pacman_name VARCHAR(255) NOT NULL DEFAULT '',
    apt_name VARCHAR(255) NOT NULL DEFAULT '',
    winget_id VARCHAR(255) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_packages_name ON packages(name);

CREATE TABLE fleet_settings (
    id INTEGER PRIMARY KEY DEFAULT 1,
    default_metrics_interval_seconds INTEGER NOT NULL DEFAULT 60,
    default_inventory_interval_seconds INTEGER NOT NULL DEFAULT 900,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE vulnerability_schedules (
    device_id VARCHAR(36) PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    interval_hours INTEGER NOT NULL DEFAULT 0,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE patch_approvals (
    device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    package_key VARCHAR(255) NOT NULL,
    available_version VARCHAR(255) NOT NULL,
    approved BOOLEAN NOT NULL DEFAULT false,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (device_id, package_key, available_version)
);

CREATE TABLE patch_schedules (
    device_id VARCHAR(36) PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    interval_hours INTEGER NOT NULL DEFAULT 0,
    next_run_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE custom_packages (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    platform VARCHAR(20) NOT NULL,
    command TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE custom_package_files (
    id VARCHAR(36) PRIMARY KEY,
    package_id VARCHAR(36) NOT NULL REFERENCES custom_packages(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    size INTEGER NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    content BYTEA NOT NULL
);
CREATE INDEX ix_custom_package_files_package_id ON custom_package_files(package_id);

CREATE TABLE integrations (
    id VARCHAR(36) PRIMARY KEY,
    kind VARCHAR(20) NOT NULL,
    name VARCHAR(255) NOT NULL,
    base_url VARCHAR(500) NOT NULL,
    verify_tls BOOLEAN NOT NULL DEFAULT true,
    encrypted_credentials TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_synced_at TIMESTAMPTZ NULL,
    last_sync_error TEXT NULL,
    cached_data JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE compliance_snapshots (
    id SERIAL PRIMARY KEY,
    device_id VARCHAR(36) NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    snapshot_date VARCHAR(10) NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    update_count INTEGER NOT NULL DEFAULT 0,
    security_update_count INTEGER NOT NULL DEFAULT 0,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    critical_vulnerability_count INTEGER NOT NULL DEFAULT 0,
    high_vulnerability_count INTEGER NOT NULL DEFAULT 0,
    online BOOLEAN NOT NULL DEFAULT false,
    CONSTRAINT uq_compliance_snapshot_device_day UNIQUE (device_id, snapshot_date)
);
CREATE INDEX ix_compliance_snapshots_device_id ON compliance_snapshots(device_id);
CREATE INDEX ix_compliance_snapshots_snapshot_date ON compliance_snapshots(snapshot_date);
