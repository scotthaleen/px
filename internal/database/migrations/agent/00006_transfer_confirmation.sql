-- +goose Up
CREATE TABLE transfer_resumes_v4 (
    direction TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
    transfer_id TEXT NOT NULL,
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE,
    peer_device_id TEXT NOT NULL,
    peer_label TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    source_size INTEGER NOT NULL CHECK (source_size >= 0),
    source_sha256 TEXT NOT NULL,
    chunk_size INTEGER NOT NULL,
    ack_window INTEGER NOT NULL,
    resume_token TEXT NOT NULL,
    acknowledged_bytes INTEGER NOT NULL DEFAULT 0,
    source_path TEXT,
    stdin_spool INTEGER NOT NULL DEFAULT 0 CHECK (stdin_spool IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('transferring', 'committing', 'committed_pending_confirmation', 'committed', 'corrupt')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    manifest_version INTEGER NOT NULL DEFAULT 2 CHECK (manifest_version IN (2, 3)),
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'public')),
    PRIMARY KEY (direction, transfer_id)
);
INSERT INTO transfer_resumes_v4 SELECT
    direction, transfer_id, context_name, peer_device_id, peer_label,
    destination_name, source_size, source_sha256, chunk_size, ack_window,
    resume_token, acknowledged_bytes, source_path, stdin_spool,
    state,
    created_at, updated_at, expires_at, manifest_version, visibility
FROM transfer_resumes;
DROP TABLE transfer_resumes;
ALTER TABLE transfer_resumes_v4 RENAME TO transfer_resumes;
CREATE INDEX transfer_resumes_expiry ON transfer_resumes(expires_at);
CREATE INDEX transfer_resumes_context_updated ON transfer_resumes(context_name, updated_at DESC, direction, transfer_id);
CREATE TABLE transfer_cleanup (
    direction TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
    transfer_id TEXT NOT NULL,
    original_name TEXT NOT NULL,
    staged_name TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK (phase IN ('intent', 'renamed')),
    created_at INTEGER NOT NULL,
    PRIMARY KEY (direction, transfer_id)
);

-- +goose Down
CREATE TABLE transfer_cleanup_rollback_guard (
    ready INTEGER NOT NULL CHECK (ready = 1)
);
INSERT INTO transfer_cleanup_rollback_guard
SELECT CASE WHEN EXISTS (SELECT 1 FROM transfer_cleanup) THEN 0 ELSE 1 END;
DROP TABLE transfer_cleanup_rollback_guard;
DROP TABLE transfer_cleanup;
CREATE TABLE transfer_resumes_v3 (
    direction TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
    transfer_id TEXT NOT NULL,
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE,
    peer_device_id TEXT NOT NULL,
    peer_label TEXT NOT NULL,
    destination_name TEXT NOT NULL,
    source_size INTEGER NOT NULL CHECK (source_size >= 0),
    source_sha256 TEXT NOT NULL,
    chunk_size INTEGER NOT NULL,
    ack_window INTEGER NOT NULL,
    resume_token TEXT NOT NULL,
    acknowledged_bytes INTEGER NOT NULL DEFAULT 0,
    source_path TEXT,
    stdin_spool INTEGER NOT NULL DEFAULT 0 CHECK (stdin_spool IN (0, 1)),
    state TEXT NOT NULL CHECK (state IN ('transferring', 'committing', 'committed')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    manifest_version INTEGER NOT NULL DEFAULT 2 CHECK (manifest_version IN (2, 3)),
    visibility TEXT NOT NULL DEFAULT 'private' CHECK (visibility IN ('private', 'public')),
    PRIMARY KEY (direction, transfer_id)
);
INSERT INTO transfer_resumes_v3 SELECT
    direction, transfer_id, context_name, peer_device_id, peer_label,
    destination_name, source_size, source_sha256, chunk_size, ack_window,
    resume_token, acknowledged_bytes, source_path, stdin_spool,
    CASE state
        WHEN 'committed_pending_confirmation' THEN 'committed'
        WHEN 'corrupt' THEN 'transferring'
        ELSE state
    END,
    created_at, updated_at, expires_at, manifest_version, visibility
FROM transfer_resumes;
DROP TABLE transfer_resumes;
ALTER TABLE transfer_resumes_v3 RENAME TO transfer_resumes;
CREATE INDEX transfer_resumes_expiry ON transfer_resumes(expires_at);
