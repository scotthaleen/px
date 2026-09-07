-- +goose Up
CREATE TABLE transfer_resumes (
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
CREATE INDEX transfer_resumes_expiry ON transfer_resumes(expires_at);

-- +goose Down
DROP TABLE transfer_resumes;
