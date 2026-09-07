-- +goose Up
CREATE TABLE contexts (
    name TEXT PRIMARY KEY,
    server_url TEXT NOT NULL,
    server_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    private_key_path TEXT NOT NULL,
    public_key_path TEXT NOT NULL,
    label TEXT NOT NULL,
    credential TEXT,
    pending_code TEXT,
    pending_expires_at INTEGER,
    state TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    offered_root TEXT NOT NULL,
    inbox_root TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE context_settings (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    default_context TEXT REFERENCES contexts(name)
);
INSERT INTO context_settings (singleton) VALUES (1);

CREATE TABLE context_aliases (
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE,
    alias TEXT NOT NULL,
    target_label TEXT NOT NULL,
    PRIMARY KEY (context_name, alias)
);

-- +goose Down
DROP TABLE context_aliases;
DROP TABLE context_settings;
DROP TABLE contexts;
