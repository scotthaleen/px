-- +goose Up
CREATE TABLE pending_enrollments (
    code TEXT PRIMARY KEY,
    device_id TEXT NOT NULL UNIQUE,
    device_key TEXT NOT NULL,
    label TEXT NOT NULL,
    label_key TEXT NOT NULL UNIQUE,
    source_ip TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX pending_enrollments_expires_at_idx ON pending_enrollments (expires_at);

CREATE TABLE members (
    device_id TEXT PRIMARY KEY,
    device_key TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    label_key TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL CHECK (revision > 0),
    credential TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at INTEGER NOT NULL,
    actor_type TEXT NOT NULL,
    actor_device_id TEXT,
    action TEXT NOT NULL,
    target_device_id TEXT,
    target_label TEXT
);

CREATE INDEX audit_events_occurred_at_idx ON audit_events (occurred_at);

-- +goose Down
DROP TABLE audit_events;
DROP TABLE members;
DROP TABLE pending_enrollments;
