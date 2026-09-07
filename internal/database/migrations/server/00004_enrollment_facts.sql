-- +goose Up
ALTER TABLE pending_enrollments ADD COLUMN enrollment_id TEXT;
ALTER TABLE members ADD COLUMN enrollment_id TEXT;
UPDATE pending_enrollments SET enrollment_id = lower(hex(randomblob(16)));
UPDATE members SET enrollment_id = lower(hex(randomblob(16)));
CREATE UNIQUE INDEX pending_enrollments_enrollment_id_idx ON pending_enrollments(enrollment_id);
CREATE UNIQUE INDEX members_enrollment_id_idx ON members(enrollment_id);
CREATE TRIGGER pending_enrollments_enrollment_id_insert BEFORE INSERT ON pending_enrollments
WHEN NEW.enrollment_id IS NULL OR length(NEW.enrollment_id) <> 32 OR NEW.enrollment_id GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT, 'invalid enrollment_id'); END;
CREATE TRIGGER pending_enrollments_enrollment_id_update BEFORE UPDATE OF enrollment_id ON pending_enrollments
WHEN NEW.enrollment_id IS NULL OR NEW.enrollment_id <> OLD.enrollment_id
BEGIN SELECT RAISE(ABORT, 'enrollment_id is immutable'); END;
CREATE TRIGGER members_enrollment_id_insert BEFORE INSERT ON members
WHEN NEW.enrollment_id IS NULL OR length(NEW.enrollment_id) <> 32 OR NEW.enrollment_id GLOB '*[^0-9a-f]*'
BEGIN SELECT RAISE(ABORT, 'invalid enrollment_id'); END;
CREATE TRIGGER members_enrollment_id_update BEFORE UPDATE OF enrollment_id ON members
WHEN NEW.enrollment_id IS NULL OR NEW.enrollment_id <> OLD.enrollment_id
BEGIN SELECT RAISE(ABORT, 'enrollment_id is immutable'); END;

ALTER TABLE audit_events ADD COLUMN actor_id TEXT;
CREATE TRIGGER audit_events_actor_insert BEFORE INSERT ON audit_events
WHEN NOT (
    (NEW.actor_type = 'adapter' AND NEW.actor_device_id IS NULL AND NEW.actor_id IS NOT NULL AND length(NEW.actor_id) BETWEEN 1 AND 64 AND NEW.actor_id NOT GLOB '*[^a-z0-9._-]*' AND NEW.actor_id GLOB '[a-z0-9]*') OR
    (NEW.actor_type = 'local' AND NEW.actor_device_id IS NULL AND NEW.actor_id IS NULL) OR
    (NEW.actor_type IN ('member', 'device') AND NEW.actor_device_id IS NOT NULL AND NEW.actor_id IS NULL)
)
BEGIN SELECT RAISE(ABORT, 'invalid audit actor'); END;
CREATE TRIGGER audit_events_immutable BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

CREATE TABLE enrollment_fact_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    replay_floor INTEGER NOT NULL DEFAULT 0 CHECK (replay_floor >= 0)
);
INSERT INTO enrollment_fact_metadata(singleton, replay_floor) VALUES (1, 0);

CREATE TABLE enrollment_facts (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN (
        'enrollment.pending_admitted',
        'enrollment.pending_expired',
        'enrollment.member_approved',
        'enrollment.member_revoked'
    )),
    enrollment_id TEXT NOT NULL CHECK (length(enrollment_id) = 32 AND enrollment_id NOT GLOB '*[^0-9a-f]*'),
    occurred_at INTEGER NOT NULL,
    device_id TEXT NOT NULL,
    label TEXT NOT NULL,
    expires_at INTEGER,
    member_revision INTEGER,
    UNIQUE(kind, enrollment_id),
    CHECK (
        (kind = 'enrollment.pending_admitted' AND expires_at IS NOT NULL AND member_revision IS NULL) OR
        (kind = 'enrollment.pending_expired' AND expires_at IS NULL AND member_revision IS NULL) OR
        (kind IN ('enrollment.member_approved', 'enrollment.member_revoked') AND expires_at IS NULL AND member_revision IS NOT NULL AND member_revision > 0)
    )
);
CREATE INDEX enrollment_facts_enrollment_seq_idx ON enrollment_facts(enrollment_id, seq);
CREATE TRIGGER enrollment_facts_immutable BEFORE UPDATE ON enrollment_facts
BEGIN SELECT RAISE(ABORT, 'enrollment facts are immutable'); END;
CREATE TRIGGER enrollment_facts_order BEFORE INSERT ON enrollment_facts
WHEN NOT (
    (NEW.kind = 'enrollment.pending_admitted' AND NOT EXISTS (SELECT 1 FROM enrollment_facts WHERE enrollment_id = NEW.enrollment_id)) OR
    (NEW.kind IN ('enrollment.pending_expired', 'enrollment.member_approved') AND
        EXISTS (SELECT 1 FROM enrollment_facts WHERE enrollment_id = NEW.enrollment_id AND kind = 'enrollment.pending_admitted') AND
        NOT EXISTS (SELECT 1 FROM enrollment_facts WHERE enrollment_id = NEW.enrollment_id AND kind IN ('enrollment.pending_expired', 'enrollment.member_approved', 'enrollment.member_revoked'))) OR
    (NEW.kind = 'enrollment.member_revoked' AND
        NOT EXISTS (SELECT 1 FROM enrollment_facts WHERE enrollment_id = NEW.enrollment_id AND kind IN ('enrollment.pending_expired', 'enrollment.member_revoked')) AND
        (EXISTS (SELECT 1 FROM enrollment_facts WHERE enrollment_id = NEW.enrollment_id AND kind = 'enrollment.member_approved') OR
         (NOT EXISTS (SELECT 1 FROM enrollment_facts WHERE enrollment_id = NEW.enrollment_id AND kind = 'enrollment.pending_admitted') AND
          EXISTS (SELECT 1 FROM members WHERE enrollment_id = NEW.enrollment_id))))
)
BEGIN SELECT RAISE(ABORT, 'invalid enrollment fact order'); END;
INSERT INTO enrollment_facts(kind, enrollment_id, occurred_at, device_id, label, expires_at)
SELECT 'enrollment.pending_admitted', enrollment_id, created_at, device_id, label, expires_at
FROM pending_enrollments
ORDER BY created_at, code;

CREATE TABLE enrollment_adapters (
    adapter_id TEXT NOT NULL PRIMARY KEY,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    credential_hash BLOB NOT NULL CHECK (length(credential_hash) = 32),
    last_command_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    CHECK (length(adapter_id) BETWEEN 1 AND 64 AND adapter_id NOT GLOB '*[^a-z0-9._-]*' AND adapter_id GLOB '[a-z0-9]*')
);
CREATE TRIGGER enrollment_adapters_capacity BEFORE INSERT ON enrollment_adapters
WHEN (SELECT count(*) FROM enrollment_adapters) >= 64
BEGIN SELECT RAISE(ABORT, 'adapter capacity'); END;
CREATE TRIGGER enrollment_adapters_identity BEFORE UPDATE OF adapter_id ON enrollment_adapters
WHEN NEW.adapter_id IS NULL OR NEW.adapter_id <> OLD.adapter_id
BEGIN SELECT RAISE(ABORT, 'adapter_id is immutable'); END;
CREATE TRIGGER enrollment_adapters_no_delete BEFORE DELETE ON enrollment_adapters
BEGIN SELECT RAISE(ABORT, 'adapter rows are permanent'); END;

CREATE TABLE enrollment_command_receipts (
    adapter_id TEXT NOT NULL REFERENCES enrollment_adapters(adapter_id),
    command_id TEXT NOT NULL,
    receipt_seq INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint BLOB NOT NULL CHECK (length(fingerprint) = 32),
    schema_version INTEGER NOT NULL CHECK (schema_version = 1),
    action TEXT NOT NULL CHECK (action = 'enrollment.approve'),
    enrollment_id TEXT NOT NULL CHECK (length(enrollment_id) = 32 AND enrollment_id NOT GLOB '*[^0-9a-f]*'),
    state TEXT NOT NULL CHECK (state IN ('admitted', 'committed', 'rejected')),
    admitted_at INTEGER NOT NULL,
    settled_at INTEGER,
    rejection_code TEXT,
    result_device_id TEXT,
    result_label TEXT,
    result_revision INTEGER,
    UNIQUE(adapter_id, command_id),
    CHECK (
        (state = 'admitted' AND settled_at IS NULL AND rejection_code IS NULL AND result_device_id IS NULL AND result_label IS NULL AND result_revision IS NULL) OR
        (state = 'committed' AND settled_at IS NOT NULL AND rejection_code IS NULL AND result_device_id IS NOT NULL AND result_label IS NOT NULL AND result_revision IS NOT NULL AND result_revision > 0) OR
        (state = 'rejected' AND settled_at IS NOT NULL AND rejection_code IS NOT NULL AND rejection_code IN ('enrollment_expired', 'settled_elsewhere', 'not_pending', 'member_capacity', 'invalid_enrollment_key') AND result_device_id IS NULL AND result_label IS NULL AND result_revision IS NULL)
    )
);
CREATE INDEX enrollment_command_receipts_state_seq_idx ON enrollment_command_receipts(state, receipt_seq);
CREATE INDEX enrollment_command_receipts_settled_idx ON enrollment_command_receipts(settled_at) WHERE settled_at IS NOT NULL;
CREATE TRIGGER enrollment_command_receipts_transition BEFORE UPDATE ON enrollment_command_receipts
WHEN OLD.state <> 'admitted' OR NEW.adapter_id <> OLD.adapter_id OR NEW.command_id <> OLD.command_id OR
    NEW.receipt_seq <> OLD.receipt_seq OR NEW.fingerprint <> OLD.fingerprint OR NEW.schema_version <> OLD.schema_version OR
    NEW.action <> OLD.action OR NEW.enrollment_id <> OLD.enrollment_id OR NEW.admitted_at <> OLD.admitted_at OR
    NEW.state NOT IN ('committed', 'rejected')
BEGIN SELECT RAISE(ABORT, 'invalid receipt transition'); END;

-- +goose Down
CREATE TABLE enrollment_facts_rollback_guard (
    ready INTEGER NOT NULL CHECK (ready = 1)
);
INSERT INTO enrollment_facts_rollback_guard
SELECT CASE WHEN
    EXISTS (SELECT 1 FROM enrollment_facts WHERE kind <> 'enrollment.pending_admitted') OR
    EXISTS (SELECT 1 FROM enrollment_command_receipts) OR
    EXISTS (SELECT 1 FROM enrollment_adapters) OR
    EXISTS (SELECT 1 FROM audit_events WHERE actor_type = 'adapter' OR actor_id IS NOT NULL)
THEN 0 ELSE 1 END;
DROP TABLE enrollment_facts_rollback_guard;
DROP TABLE enrollment_command_receipts;
DROP TRIGGER enrollment_adapters_no_delete;
DROP TRIGGER enrollment_adapters_identity;
DROP TRIGGER enrollment_adapters_capacity;
DROP TABLE enrollment_adapters;
DROP TABLE enrollment_facts;
DROP TABLE enrollment_fact_metadata;
DROP TRIGGER audit_events_immutable;
DROP TRIGGER audit_events_actor_insert;
DROP TRIGGER members_enrollment_id_update;
DROP TRIGGER members_enrollment_id_insert;
DROP TRIGGER pending_enrollments_enrollment_id_update;
DROP TRIGGER pending_enrollments_enrollment_id_insert;
DROP INDEX members_enrollment_id_idx;
DROP INDEX pending_enrollments_enrollment_id_idx;
ALTER TABLE audit_events DROP COLUMN actor_id;
ALTER TABLE members DROP COLUMN enrollment_id;
ALTER TABLE pending_enrollments DROP COLUMN enrollment_id;
