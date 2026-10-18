-- A saved, reusable script library (server-rs/src/scripts.rs): running one
-- against a device dispatches the exact same RUN_COMMAND job type the
-- ad-hoc "Run command" feature already uses (deployment.rs::run_command),
-- so no agent changes were needed -- this table just gives admins a named,
-- reusable body instead of retyping (or copy-pasting) the same command
-- into that one-off box every time.
CREATE TABLE scripts (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description VARCHAR(500) NOT NULL DEFAULT '',
    platform VARCHAR(20) NOT NULL DEFAULT 'any',
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
