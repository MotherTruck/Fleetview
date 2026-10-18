-- One-time tokens for the admin "Server migration" feature
-- (server-rs/src/migration.rs): generated on the freshly-provisioned
-- target server, then pasted into the source server's admin UI, which
-- authenticates its /api/v1/admin/migration/receive request with it.
-- Single-use and short-lived, the same shape as enrollment_tokens.
CREATE TABLE migration_tokens (
    id VARCHAR(36) PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ
);
CREATE INDEX ix_migration_tokens_token_hash ON migration_tokens(token_hash);
