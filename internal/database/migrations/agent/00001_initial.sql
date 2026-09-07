-- +goose Up
CREATE TABLE app_metadata (
    component TEXT PRIMARY KEY,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT INTO app_metadata (component) VALUES ('agent');

-- +goose Down
DROP TABLE app_metadata;
