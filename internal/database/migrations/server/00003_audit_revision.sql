-- +goose Up
ALTER TABLE audit_events ADD COLUMN target_revision INTEGER;

-- +goose Down
ALTER TABLE audit_events DROP COLUMN target_revision;
