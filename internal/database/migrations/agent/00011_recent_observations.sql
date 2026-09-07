-- +goose Up
CREATE TABLE recent_observations (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE CHECK (length(context_name) BETWEEN 1 AND 63),
    direction TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
    transfer_id TEXT NOT NULL CHECK (length(transfer_id) = 64 AND transfer_id NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK (kind IN ('sender_observed_commit', 'receiver_published')),
    peer_device_id TEXT NOT NULL CHECK (length(peer_device_id) = 43),
    peer_label TEXT NOT NULL CHECK (length(peer_label) BETWEEN 1 AND 63),
    destination_name TEXT NOT NULL CHECK (length(destination_name) BETWEEN 1 AND 255),
    visibility TEXT NOT NULL CHECK (visibility IN ('private', 'public')),
    bytes INTEGER NOT NULL CHECK (bytes BETWEEN 0 AND 1073741824),
    observed_at INTEGER NOT NULL CHECK (observed_at >= 0),
    UNIQUE (context_name, direction, transfer_id),
    CHECK ((direction = 'send' AND kind = 'sender_observed_commit') OR
           (direction = 'receive' AND kind = 'receiver_published'))
);
CREATE INDEX recent_observations_context_newest ON recent_observations(context_name, observed_at DESC, sequence DESC);
CREATE INDEX recent_observations_peer_newest ON recent_observations(context_name, peer_device_id, observed_at DESC, sequence DESC);

-- +goose Down
CREATE TABLE recent_observations_rollback_guard (
    ready INTEGER NOT NULL CHECK (ready = 1)
);
INSERT INTO recent_observations_rollback_guard
SELECT CASE WHEN EXISTS (SELECT 1 FROM recent_observations) THEN 0 ELSE 1 END;
DROP TABLE recent_observations_rollback_guard;
DROP TABLE recent_observations;
