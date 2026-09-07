-- +goose Up
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
INSERT INTO transfer_resumes_v3 (
    direction, transfer_id, context_name, peer_device_id, peer_label,
    destination_name, source_size, source_sha256, chunk_size, ack_window,
    resume_token, acknowledged_bytes, source_path, stdin_spool, state,
    created_at, updated_at, expires_at, manifest_version, visibility
)
SELECT
    direction, transfer_id, context_name, peer_device_id, peer_label,
    destination_name, source_size, source_sha256, chunk_size, ack_window,
    resume_token, acknowledged_bytes, source_path, stdin_spool, state,
    created_at, updated_at, expires_at, 2, 'private'
FROM transfer_resumes;
DROP TABLE transfer_resumes;
ALTER TABLE transfer_resumes_v3 RENAME TO transfer_resumes;
CREATE INDEX transfer_resumes_expiry ON transfer_resumes(expires_at);

-- +goose Down
CREATE TABLE transfer_resumes_v2 (
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
    state TEXT NOT NULL CHECK (state IN ('transferring', 'committed')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (direction, transfer_id)
);
INSERT INTO transfer_resumes_v2 (
    direction, transfer_id, context_name, peer_device_id, peer_label,
    destination_name, source_size, source_sha256, chunk_size, ack_window,
    resume_token, acknowledged_bytes, source_path, stdin_spool, state,
    created_at, updated_at, expires_at
)
SELECT
    direction, transfer_id, context_name, peer_device_id, peer_label,
    destination_name, source_size, source_sha256, chunk_size, ack_window,
    resume_token, acknowledged_bytes, source_path, stdin_spool,
    CASE state WHEN 'committing' THEN 'transferring' ELSE state END,
    created_at, updated_at, expires_at
FROM transfer_resumes;
DROP TABLE transfer_resumes;
ALTER TABLE transfer_resumes_v2 RENAME TO transfer_resumes;
CREATE INDEX transfer_resumes_expiry ON transfer_resumes(expires_at);
