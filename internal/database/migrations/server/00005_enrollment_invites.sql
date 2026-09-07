-- +goose Up
ALTER TABLE audit_events ADD COLUMN target_invite_id TEXT;

DROP TRIGGER audit_events_actor_insert;
CREATE TRIGGER audit_events_actor_insert BEFORE INSERT ON audit_events
WHEN NOT (
    (NEW.actor_type = 'adapter' AND NEW.actor_device_id IS NULL AND NEW.actor_id IS NOT NULL AND length(NEW.actor_id) BETWEEN 1 AND 64 AND NEW.actor_id NOT GLOB '*[^a-z0-9._-]*' AND NEW.actor_id GLOB '[a-z0-9]*') OR
    (NEW.actor_type IN ('local', 'system') AND NEW.actor_device_id IS NULL AND NEW.actor_id IS NULL) OR
    (NEW.actor_type IN ('member', 'device') AND NEW.actor_device_id IS NOT NULL AND NEW.actor_id IS NULL)
)
BEGIN SELECT RAISE(ABORT, 'invalid audit actor'); END;

CREATE TRIGGER audit_events_invite_shape_insert BEFORE INSERT ON audit_events
WHEN NOT (
    (NEW.action = 'invite.created' AND NEW.actor_type IN ('local', 'member') AND
        NEW.target_invite_id IS NOT NULL AND typeof(NEW.target_invite_id) = 'text' AND length(NEW.target_invite_id) = 32 AND NEW.target_invite_id NOT GLOB '*[^0-9a-f]*' AND
        NEW.target_label IS NOT NULL AND typeof(NEW.target_label) = 'text' AND length(NEW.target_label) BETWEEN 1 AND 63 AND NEW.target_label GLOB '[A-Za-z0-9]*' AND NEW.target_label NOT GLOB '*[^A-Za-z0-9._-]*' AND
        NEW.target_device_id IS NULL AND NEW.target_revision IS NULL AND
        (NEW.actor_type = 'local' OR (length(NEW.actor_device_id) = 43 AND NEW.actor_device_id NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(NEW.actor_device_id, 43, 1) GLOB '[AEIMQUYcgkosw048]'))) OR
    (NEW.action = 'invite.redeemed' AND NEW.actor_type = 'device' AND
        NEW.target_invite_id IS NOT NULL AND typeof(NEW.target_invite_id) = 'text' AND length(NEW.target_invite_id) = 32 AND NEW.target_invite_id NOT GLOB '*[^0-9a-f]*' AND
        NEW.target_label IS NOT NULL AND typeof(NEW.target_label) = 'text' AND length(NEW.target_label) BETWEEN 1 AND 63 AND NEW.target_label GLOB '[A-Za-z0-9]*' AND NEW.target_label NOT GLOB '*[^A-Za-z0-9._-]*' AND
        length(NEW.actor_device_id) = 43 AND NEW.actor_device_id NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(NEW.actor_device_id, 43, 1) GLOB '[AEIMQUYcgkosw048]' AND
        NEW.target_device_id = NEW.actor_device_id AND NEW.target_revision = 1 AND typeof(NEW.target_revision) = 'integer') OR
    (NEW.action = 'invite.revoked' AND NEW.actor_type IN ('local', 'member') AND
        NEW.target_invite_id IS NOT NULL AND typeof(NEW.target_invite_id) = 'text' AND length(NEW.target_invite_id) = 32 AND NEW.target_invite_id NOT GLOB '*[^0-9a-f]*' AND
        NEW.target_label IS NOT NULL AND typeof(NEW.target_label) = 'text' AND length(NEW.target_label) BETWEEN 1 AND 63 AND NEW.target_label GLOB '[A-Za-z0-9]*' AND NEW.target_label NOT GLOB '*[^A-Za-z0-9._-]*' AND
        NEW.target_device_id IS NULL AND NEW.target_revision IS NULL AND
        (NEW.actor_type = 'local' OR (length(NEW.actor_device_id) = 43 AND NEW.actor_device_id NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(NEW.actor_device_id, 43, 1) GLOB '[AEIMQUYcgkosw048]'))) OR
    (NEW.action = 'invite.expired' AND NEW.actor_type = 'system' AND
        NEW.target_invite_id IS NOT NULL AND typeof(NEW.target_invite_id) = 'text' AND length(NEW.target_invite_id) = 32 AND NEW.target_invite_id NOT GLOB '*[^0-9a-f]*' AND
        NEW.target_label IS NOT NULL AND typeof(NEW.target_label) = 'text' AND length(NEW.target_label) BETWEEN 1 AND 63 AND NEW.target_label GLOB '[A-Za-z0-9]*' AND NEW.target_label NOT GLOB '*[^A-Za-z0-9._-]*' AND
        NEW.target_device_id IS NULL AND NEW.target_revision IS NULL) OR
    (NEW.action NOT GLOB 'invite.*' AND NEW.target_invite_id IS NULL AND NEW.actor_type <> 'system')
)
BEGIN SELECT RAISE(ABORT, 'invalid invite audit shape'); END;

CREATE TABLE enrollment_invites (
    invite_id TEXT NOT NULL PRIMARY KEY CHECK (typeof(invite_id) = 'text' AND length(invite_id) = 32 AND invite_id NOT GLOB '*[^0-9a-f]*'),
    verifier BLOB NOT NULL CHECK (typeof(verifier) = 'blob' AND length(verifier) = 32),
    label TEXT NOT NULL CHECK (typeof(label) = 'text' AND length(label) BETWEEN 1 AND 63 AND label GLOB '[A-Za-z0-9]*' AND label NOT GLOB '*[^A-Za-z0-9._-]*'),
    label_key TEXT NOT NULL UNIQUE CHECK (typeof(label_key) = 'text' AND label_key = lower(label) AND length(label_key) BETWEEN 1 AND 63 AND label_key GLOB '[a-z0-9]*' AND label_key NOT GLOB '*[^a-z0-9._-]*'),
    issuer_type TEXT NOT NULL CHECK (issuer_type IN ('local', 'member')),
    issuer_device_id TEXT REFERENCES members(device_id),
    created_at INTEGER NOT NULL CHECK (typeof(created_at) = 'integer' AND created_at >= 0),
    expires_at INTEGER NOT NULL CHECK (typeof(expires_at) = 'integer' AND expires_at - created_at BETWEEN 60 AND 604800),
    CHECK (
        (issuer_type = 'local' AND issuer_device_id IS NULL) OR
        (issuer_type = 'member' AND issuer_device_id IS NOT NULL AND typeof(issuer_device_id) = 'text' AND length(issuer_device_id) = 43 AND issuer_device_id NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(issuer_device_id, 43, 1) GLOB '[AEIMQUYcgkosw048]')
    )
);
CREATE INDEX enrollment_invites_expiry_idx ON enrollment_invites(expires_at, invite_id);
CREATE INDEX enrollment_invites_issuer_idx ON enrollment_invites(issuer_device_id, created_at);
CREATE TRIGGER enrollment_invites_immutable BEFORE UPDATE ON enrollment_invites
BEGIN SELECT RAISE(ABORT, 'enrollment invites are immutable'); END;
CREATE TRIGGER enrollment_invites_capacity BEFORE INSERT ON enrollment_invites
WHEN (SELECT count(*) FROM enrollment_invites) >= 64
BEGIN SELECT RAISE(ABORT, 'invite capacity'); END;
CREATE TRIGGER enrollment_invites_member_capacity BEFORE INSERT ON enrollment_invites
WHEN NEW.issuer_type = 'member' AND (SELECT count(*) FROM enrollment_invites WHERE issuer_device_id = NEW.issuer_device_id) >= 16
BEGIN SELECT RAISE(ABORT, 'member invite capacity'); END;

-- +goose Down
CREATE TABLE enrollment_invites_rollback_guard (
    ready INTEGER NOT NULL CHECK (ready = 1)
);
INSERT INTO enrollment_invites_rollback_guard
SELECT CASE WHEN
    EXISTS (SELECT 1 FROM enrollment_invites) OR
    EXISTS (SELECT 1 FROM audit_events WHERE action IN ('invite.created', 'invite.redeemed', 'invite.revoked', 'invite.expired') OR target_invite_id IS NOT NULL OR actor_type = 'system')
THEN 0 ELSE 1 END;
DROP TABLE enrollment_invites_rollback_guard;
DROP TRIGGER enrollment_invites_member_capacity;
DROP TRIGGER enrollment_invites_capacity;
DROP TRIGGER enrollment_invites_immutable;
DROP TABLE enrollment_invites;
DROP TRIGGER audit_events_invite_shape_insert;
DROP TRIGGER audit_events_actor_insert;
CREATE TRIGGER audit_events_actor_insert BEFORE INSERT ON audit_events
WHEN NOT (
    (NEW.actor_type = 'adapter' AND NEW.actor_device_id IS NULL AND NEW.actor_id IS NOT NULL AND length(NEW.actor_id) BETWEEN 1 AND 64 AND NEW.actor_id NOT GLOB '*[^a-z0-9._-]*' AND NEW.actor_id GLOB '[a-z0-9]*') OR
    (NEW.actor_type = 'local' AND NEW.actor_device_id IS NULL AND NEW.actor_id IS NULL) OR
    (NEW.actor_type IN ('member', 'device') AND NEW.actor_device_id IS NOT NULL AND NEW.actor_id IS NULL)
)
BEGIN SELECT RAISE(ABORT, 'invalid audit actor'); END;
ALTER TABLE audit_events DROP COLUMN target_invite_id;
