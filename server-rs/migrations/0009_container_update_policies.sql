-- Per-image Docker update policies (deployment.rs/container_updates.rs):
-- whether a given image is kept current automatically (Watchtower-style
-- pull+recreate) or left for an admin to apply by hand, plus which
-- devices running that image are excluded from either. One row per
-- distinct image reference (e.g. "nginx:latest") actually seen running
-- somewhere in the fleet; image_name = '*' is the fleet-wide default used
-- for any image with no row of its own, so there's always exactly one
-- place "the default" lives rather than a separate fleet_settings column
-- to keep in sync with this table.
CREATE TABLE container_update_policies (
    id VARCHAR(36) PRIMARY KEY,
    image_name VARCHAR(512) NOT NULL UNIQUE,
    mode VARCHAR(16) NOT NULL DEFAULT 'manual' CHECK (mode IN ('automatic', 'manual')),
    excluded_device_ids JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO container_update_policies (id, image_name, mode, excluded_device_ids)
VALUES ('00000000-0000-0000-0000-000000000000', '*', 'manual', '[]');
