-- +goose Up
CREATE TABLE get_cleanup (
    cleanup_id TEXT PRIMARY KEY NOT NULL
        CHECK (length(cleanup_id) = 64 AND cleanup_id NOT GLOB '*[^0-9a-f]*'),
    parent_path TEXT NOT NULL CHECK (length(parent_path) > 0 AND length(parent_path) <= 4096),
    parent_identity TEXT NOT NULL CHECK (length(parent_identity) BETWEEN 8 AND 160),
    stage_name TEXT NOT NULL UNIQUE
        CHECK (length(stage_name) = 72 AND substr(stage_name, 1, 4) = '.px-' AND substr(stage_name, 69) = '.get'
            AND substr(stage_name, 5, 64) NOT GLOB '*[^0-9a-f]*'),
    stage_identity TEXT CHECK (stage_identity IS NULL OR length(stage_identity) BETWEEN 8 AND 160),
    marker_name TEXT NOT NULL UNIQUE
        CHECK (length(marker_name) = 71 AND substr(marker_name, 1, 7) = '.owner-'
            AND substr(marker_name, 8) NOT GLOB '*[^0-9a-f]*'),
    marker_token TEXT NOT NULL
        CHECK (length(marker_token) = 64 AND marker_token NOT GLOB '*[^0-9a-f]*'),
    declared_bytes INTEGER NOT NULL CHECK (declared_bytes BETWEEN 0 AND 1073741824),
    phase TEXT NOT NULL CHECK (phase IN ('reserved', 'stage_created', 'marker_created', 'data_created', 'publishing', 'cleanup_authorized')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    expires_at INTEGER NOT NULL CHECK (expires_at >= created_at),
    next_retry_at INTEGER NOT NULL CHECK (next_retry_at >= created_at),
    expired_notified INTEGER NOT NULL DEFAULT 0 CHECK (expired_notified IN (0, 1)),
    lease_token TEXT CHECK (lease_token IS NULL OR (length(lease_token) = 64 AND lease_token NOT GLOB '*[^0-9a-f]*')),
    lease_expires_at INTEGER CHECK (lease_expires_at IS NULL OR lease_expires_at >= created_at),
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
    CHECK ((phase = 'reserved' AND stage_identity IS NULL) OR (phase != 'reserved' AND stage_identity IS NOT NULL))
);
CREATE INDEX get_cleanup_due ON get_cleanup(parent_path, parent_identity, next_retry_at, lease_expires_at, created_at, cleanup_id);

-- +goose Down
CREATE TABLE get_cleanup_rollback_guard (ready INTEGER NOT NULL CHECK (ready = 1));
INSERT INTO get_cleanup_rollback_guard SELECT CASE WHEN EXISTS (SELECT 1 FROM get_cleanup) THEN 0 ELSE 1 END;
DROP TABLE get_cleanup_rollback_guard;
DROP TABLE get_cleanup;
