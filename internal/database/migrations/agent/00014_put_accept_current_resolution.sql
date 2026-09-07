-- +goose Up
DROP TRIGGER transfer_shared_quota_insert;
DROP TRIGGER put_shared_quota_insert;
DROP INDEX put_transfers_due_parent;
DROP INDEX put_transfers_context_updated;
ALTER TABLE put_transfers RENAME TO put_transfers_resolution_old;

CREATE TABLE put_transfers (
    direction TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
    transfer_id TEXT NOT NULL CHECK (length(transfer_id) = 32 AND transfer_id NOT GLOB '*[^0-9a-f]*'),
    protocol_version INTEGER NOT NULL DEFAULT 2 CHECK (protocol_version = 2),
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE,
    peer_device_id TEXT NOT NULL CHECK (length(peer_device_id) > 0),
    local_device_id TEXT NOT NULL CHECK (length(local_device_id) > 0),
    peer_label TEXT NOT NULL CHECK (length(peer_label) BETWEEN 1 AND 255),
    destination TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 4096),
    mode TEXT NOT NULL CHECK (mode IN ('create', 'replace')),
    expected_sha256 TEXT CHECK (expected_sha256 IS NULL OR (length(expected_sha256) = 64 AND expected_sha256 NOT GLOB '*[^0-9a-f]*')),
    source_size INTEGER NOT NULL CHECK (source_size BETWEEN 0 AND 1073741824),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    chunk_size INTEGER NOT NULL CHECK (chunk_size = 32768),
    ack_window INTEGER NOT NULL CHECK (ack_window = 8),
    put_root_revision INTEGER NOT NULL CHECK (put_root_revision > 0),
    source_path TEXT CHECK (source_path IS NULL OR length(source_path) BETWEEN 1 AND 4096),
    parent_path TEXT CHECK (parent_path IS NULL OR length(parent_path) BETWEEN 1 AND 4096),
    parent_identity TEXT CHECK (parent_identity IS NULL OR length(parent_identity) BETWEEN 8 AND 160),
    stage_name TEXT,
    stage_identity TEXT CHECK (stage_identity IS NULL OR length(stage_identity) BETWEEN 8 AND 160),
    old_identity TEXT CHECK (old_identity IS NULL OR length(old_identity) BETWEEN 8 AND 160),
    old_uid INTEGER CHECK (old_uid IS NULL OR old_uid BETWEEN 0 AND 4294967295),
    old_gid INTEGER CHECK (old_gid IS NULL OR old_gid BETWEEN 0 AND 4294967295),
    old_mode INTEGER CHECK (old_mode IS NULL OR old_mode BETWEEN 0 AND 4095),
    old_metadata TEXT CHECK (old_metadata IS NULL OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL
        AND length(old_metadata) BETWEEN 16 AND 160)),
    backup_name TEXT CHECK (backup_name IS NULL OR (direction = 'receive' AND mode = 'replace' AND length(backup_name) = 40
        AND substr(backup_name, 1, 4) = '.px-' AND substr(backup_name, 37) = '.bak'
        AND substr(backup_name, 5, 32) NOT GLOB '*[^0-9a-f]*')),
    backup_identity TEXT CHECK (backup_identity IS NULL OR (direction = 'receive' AND mode = 'replace' AND length(backup_identity) BETWEEN 8 AND 160)),
    backup_size INTEGER NOT NULL DEFAULT 0 CHECK ((backup_name IS NULL AND backup_identity IS NULL AND backup_size = 0)
        OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL AND backup_identity IS NOT NULL
            AND old_metadata IS NOT NULL AND backup_size BETWEEN 0 AND 4294967296)),
    state TEXT NOT NULL CHECK (state IN ('stage_intent', 'transferring', 'publication_intent', 'cleanup_not_attempted', 'committed', 'outcome_unknown', 'accept_current_intent', 'resolved_accept_current')),
    acknowledged_bytes INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_bytes BETWEEN 0 AND source_size),
    created INTEGER NOT NULL DEFAULT 0 CHECK (created IN (0, 1)),
    replaced INTEGER NOT NULL DEFAULT 0 CHECK (replaced IN (0, 1)),
    durability TEXT CHECK (durability IS NULL OR durability IN ('durability_confirmed', 'durability_unconfirmed')),
    stage_removed INTEGER NOT NULL DEFAULT 0 CHECK (stage_removed IN (0, 1)),
    backup_removed INTEGER NOT NULL DEFAULT 0,
    parent_synced INTEGER NOT NULL DEFAULT 0 CHECK (parent_synced IN (0, 1)),
    resolution_destination_identity TEXT CHECK (resolution_destination_identity IS NULL OR length(resolution_destination_identity) BETWEEN 8 AND 160),
    resolved_at INTEGER CHECK (resolved_at IS NULL OR resolved_at >= created_at),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    expires_at INTEGER NOT NULL CHECK (expires_at >= created_at),
    next_retry_at INTEGER NOT NULL CHECK (next_retry_at >= created_at),
    lease_token TEXT CHECK (lease_token IS NULL OR (length(lease_token) = 64 AND lease_token NOT GLOB '*[^0-9a-f]*')),
    lease_expires_at INTEGER CHECK (lease_expires_at IS NULL OR lease_expires_at >= created_at),
    PRIMARY KEY (direction, transfer_id),
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
    CHECK (expected_sha256 IS NULL OR mode = 'replace'),
    CHECK ((direction = 'send' AND source_path IS NOT NULL AND parent_path IS NULL AND parent_identity IS NULL AND stage_name IS NULL AND stage_identity IS NULL AND old_identity IS NULL AND old_uid IS NULL AND old_gid IS NULL AND old_mode IS NULL AND old_metadata IS NULL AND backup_name IS NULL AND backup_identity IS NULL AND backup_size = 0 AND stage_removed = 0 AND backup_removed = 0 AND parent_synced = 0)
        OR (direction = 'receive' AND source_path IS NULL)),
    CHECK ((stage_name IS NULL AND stage_identity IS NULL AND parent_path IS NULL AND parent_identity IS NULL)
        OR (direction = 'receive' AND stage_name IS NOT NULL AND parent_path IS NOT NULL AND parent_identity IS NOT NULL)),
    CHECK ((old_identity IS NULL AND old_uid IS NULL AND old_gid IS NULL AND old_mode IS NULL)
        OR (direction = 'receive' AND mode = 'replace' AND old_identity IS NOT NULL AND old_uid IS NOT NULL AND old_gid IS NOT NULL AND old_mode IS NOT NULL)),
    CHECK (direction = 'send' OR (mode = 'create' AND old_identity IS NULL) OR (mode = 'replace' AND old_identity IS NOT NULL)),
    CHECK (stage_name IS NULL OR (length(stage_name) = 40 AND substr(stage_name, 1, 4) = '.px-' AND substr(stage_name, 37) = '.put'
        AND substr(stage_name, 5, 32) NOT GLOB '*[^0-9a-f]*')),
    CHECK (backup_removed IN (0, 1)
        AND (backup_removed = 0 OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL
            AND state IN ('cleanup_not_attempted', 'committed', 'accept_current_intent')))
        AND (parent_synced = 0 OR backup_name IS NULL OR backup_removed = 1)),
    CHECK (parent_synced = 0 OR stage_removed = 1),
    CHECK (stage_removed = 0 OR (direction = 'receive' AND stage_name IS NOT NULL AND state IN ('cleanup_not_attempted', 'committed', 'accept_current_intent'))),
    CHECK (created + replaced <= 1),
    CHECK ((state IN ('accept_current_intent', 'resolved_accept_current') AND direction = 'receive' AND resolution_destination_identity IS NOT NULL)
        OR (state NOT IN ('accept_current_intent', 'resolved_accept_current') AND resolution_destination_identity IS NULL AND resolved_at IS NULL)),
    CHECK ((state = 'stage_intent' AND direction = 'receive' AND stage_name IS NOT NULL AND stage_identity IS NULL AND stage_removed = 0 AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'transferring' AND created = 0 AND replaced = 0 AND durability IS NULL AND (direction = 'send' OR (stage_identity IS NOT NULL AND stage_removed = 0)))
        OR (state = 'publication_intent' AND direction = 'receive' AND stage_identity IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'cleanup_not_attempted' AND direction = 'receive' AND stage_name IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'committed' AND durability IS NOT NULL AND ((mode = 'create' AND created = 1 AND replaced = 0) OR (mode = 'replace' AND created = 0 AND replaced = 1)))
        OR (state = 'outcome_unknown' AND direction = 'receive' AND stage_identity IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'accept_current_intent' AND direction = 'receive' AND stage_name IS NOT NULL AND stage_identity IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL AND resolved_at IS NULL)
        OR (state = 'resolved_accept_current' AND direction = 'receive' AND parent_path IS NULL AND parent_identity IS NULL AND stage_name IS NULL AND stage_identity IS NULL AND old_metadata IS NULL AND backup_name IS NULL AND backup_identity IS NULL AND backup_size = 0 AND stage_removed = 0 AND backup_removed = 0 AND parent_synced = 0 AND created = 0 AND replaced = 0 AND durability IS NULL AND resolved_at IS NOT NULL))
);

INSERT INTO put_transfers(direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,parent_path,parent_identity,stage_name,stage_identity,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,acknowledged_bytes,created,replaced,durability,stage_removed,backup_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at)
SELECT direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,parent_path,parent_identity,stage_name,stage_identity,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,acknowledged_bytes,created,replaced,durability,stage_removed,backup_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at FROM put_transfers_resolution_old;
DROP TABLE put_transfers_resolution_old;

CREATE INDEX put_transfers_context_updated ON put_transfers(context_name, updated_at DESC, direction, transfer_id);
CREATE INDEX put_transfers_due_parent ON put_transfers(parent_path, parent_identity, next_retry_at, created_at, transfer_id);

-- +goose StatementBegin
CREATE TRIGGER put_accept_current_insert_guard BEFORE INSERT ON put_transfers
WHEN NEW.state IN ('accept_current_intent','resolved_accept_current')
BEGIN
    SELECT RAISE(ABORT, 'put accept-current state must be entered by transition');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER put_accept_current_transition_guard BEFORE UPDATE OF state ON put_transfers
WHEN (NEW.state = 'accept_current_intent' AND OLD.state != 'outcome_unknown')
    OR (NEW.state = 'resolved_accept_current' AND OLD.state != 'accept_current_intent')
    OR (OLD.state = 'accept_current_intent' AND NEW.state NOT IN ('accept_current_intent','resolved_accept_current'))
    OR (OLD.state = 'resolved_accept_current' AND NEW.state != 'resolved_accept_current')
BEGIN
    SELECT RAISE(ABORT, 'invalid put accept-current state transition');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER put_shared_quota_insert BEFORE INSERT ON put_transfers BEGIN
    SELECT CASE WHEN NEW.direction = 'send' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'send') +
        (SELECT count(*) FROM put_transfers WHERE direction = 'send') >= 64
        THEN RAISE(ABORT, 'shared sender transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state NOT IN ('committed','resolved_accept_current') OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) >= 64
        THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT coalesce(sum(source_size + backup_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state NOT IN ('committed','resolved_accept_current') OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) > 4294967296 - NEW.source_size - NEW.backup_size
        THEN RAISE(ABORT, 'shared receiver byte capacity reached') END;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER transfer_shared_quota_insert BEFORE INSERT ON transfer_resumes BEGIN
    SELECT CASE WHEN NEW.direction = 'send' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'send') +
        (SELECT count(*) FROM put_transfers WHERE direction = 'send') >= 64
        THEN RAISE(ABORT, 'shared sender transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state NOT IN ('committed','resolved_accept_current') OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) >= 64
        THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT coalesce(sum(source_size + backup_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state NOT IN ('committed','resolved_accept_current') OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) > 4294967296 - NEW.source_size
        THEN RAISE(ABORT, 'shared receiver byte capacity reached') END;
END;
-- +goose StatementEnd

-- +goose Down
CREATE TEMP TABLE put_accept_current_rollback_guard(value INTEGER CHECK (value = 0));
INSERT INTO put_accept_current_rollback_guard
SELECT count(*) FROM put_transfers WHERE state IN ('accept_current_intent','resolved_accept_current') OR resolution_destination_identity IS NOT NULL OR resolved_at IS NOT NULL;
DROP TABLE put_accept_current_rollback_guard;
DROP TRIGGER transfer_shared_quota_insert;
DROP TRIGGER put_shared_quota_insert;
DROP TRIGGER put_accept_current_transition_guard;
DROP TRIGGER put_accept_current_insert_guard;
DROP INDEX put_transfers_due_parent;
DROP INDEX put_transfers_context_updated;
ALTER TABLE put_transfers RENAME TO put_transfers_resolution;

CREATE TABLE put_transfers (
    direction TEXT NOT NULL CHECK (direction IN ('send', 'receive')),
    transfer_id TEXT NOT NULL CHECK (length(transfer_id) = 32 AND transfer_id NOT GLOB '*[^0-9a-f]*'),
    protocol_version INTEGER NOT NULL DEFAULT 2 CHECK (protocol_version = 2),
    context_name TEXT NOT NULL REFERENCES contexts(name) ON DELETE CASCADE,
    peer_device_id TEXT NOT NULL CHECK (length(peer_device_id) > 0),
    local_device_id TEXT NOT NULL CHECK (length(local_device_id) > 0),
    peer_label TEXT NOT NULL CHECK (length(peer_label) BETWEEN 1 AND 255),
    destination TEXT NOT NULL CHECK (length(destination) BETWEEN 1 AND 4096),
    mode TEXT NOT NULL CHECK (mode IN ('create', 'replace')),
    expected_sha256 TEXT CHECK (expected_sha256 IS NULL OR (length(expected_sha256) = 64 AND expected_sha256 NOT GLOB '*[^0-9a-f]*')),
    source_size INTEGER NOT NULL CHECK (source_size BETWEEN 0 AND 1073741824),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    chunk_size INTEGER NOT NULL CHECK (chunk_size = 32768),
    ack_window INTEGER NOT NULL CHECK (ack_window = 8),
    put_root_revision INTEGER NOT NULL CHECK (put_root_revision > 0),
    source_path TEXT CHECK (source_path IS NULL OR length(source_path) BETWEEN 1 AND 4096),
    parent_path TEXT CHECK (parent_path IS NULL OR length(parent_path) BETWEEN 1 AND 4096),
    parent_identity TEXT CHECK (parent_identity IS NULL OR length(parent_identity) BETWEEN 8 AND 160),
    stage_name TEXT,
    stage_identity TEXT CHECK (stage_identity IS NULL OR length(stage_identity) BETWEEN 8 AND 160),
    old_identity TEXT CHECK (old_identity IS NULL OR length(old_identity) BETWEEN 8 AND 160),
    old_uid INTEGER CHECK (old_uid IS NULL OR old_uid BETWEEN 0 AND 4294967295),
    old_gid INTEGER CHECK (old_gid IS NULL OR old_gid BETWEEN 0 AND 4294967295),
    old_mode INTEGER CHECK (old_mode IS NULL OR old_mode BETWEEN 0 AND 4095),
    old_metadata TEXT CHECK (old_metadata IS NULL OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL AND length(old_metadata) BETWEEN 16 AND 160)),
    backup_name TEXT CHECK (backup_name IS NULL OR (direction = 'receive' AND mode = 'replace' AND length(backup_name) = 40 AND substr(backup_name, 1, 4) = '.px-' AND substr(backup_name, 37) = '.bak' AND substr(backup_name, 5, 32) NOT GLOB '*[^0-9a-f]*')),
    backup_identity TEXT CHECK (backup_identity IS NULL OR (direction = 'receive' AND mode = 'replace' AND length(backup_identity) BETWEEN 8 AND 160)),
    backup_size INTEGER NOT NULL DEFAULT 0 CHECK ((backup_name IS NULL AND backup_identity IS NULL AND backup_size = 0) OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL AND backup_identity IS NOT NULL AND old_metadata IS NOT NULL AND backup_size BETWEEN 0 AND 4294967296)),
    state TEXT NOT NULL CHECK (state IN ('stage_intent', 'transferring', 'publication_intent', 'cleanup_not_attempted', 'committed', 'outcome_unknown')),
    acknowledged_bytes INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged_bytes BETWEEN 0 AND source_size),
    created INTEGER NOT NULL DEFAULT 0 CHECK (created IN (0, 1)),
    replaced INTEGER NOT NULL DEFAULT 0 CHECK (replaced IN (0, 1)),
    durability TEXT CHECK (durability IS NULL OR durability IN ('durability_confirmed', 'durability_unconfirmed')),
    stage_removed INTEGER NOT NULL DEFAULT 0 CHECK (stage_removed IN (0, 1)),
    backup_removed INTEGER NOT NULL DEFAULT 0 CHECK (backup_removed IN (0, 1) AND (backup_removed = 0 OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL AND state IN ('cleanup_not_attempted', 'committed'))) AND (parent_synced = 0 OR backup_name IS NULL OR backup_removed = 1)),
    parent_synced INTEGER NOT NULL DEFAULT 0 CHECK (parent_synced IN (0, 1)),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL CHECK (updated_at >= created_at),
    expires_at INTEGER NOT NULL CHECK (expires_at >= created_at),
    next_retry_at INTEGER NOT NULL CHECK (next_retry_at >= created_at),
    lease_token TEXT CHECK (lease_token IS NULL OR (length(lease_token) = 64 AND lease_token NOT GLOB '*[^0-9a-f]*')),
    lease_expires_at INTEGER CHECK (lease_expires_at IS NULL OR lease_expires_at >= created_at),
    PRIMARY KEY (direction, transfer_id),
    CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
    CHECK (expected_sha256 IS NULL OR mode = 'replace'),
    CHECK ((direction = 'send' AND source_path IS NOT NULL AND parent_path IS NULL AND parent_identity IS NULL AND stage_name IS NULL AND stage_identity IS NULL AND old_identity IS NULL AND old_uid IS NULL AND old_gid IS NULL AND old_mode IS NULL AND stage_removed = 0 AND parent_synced = 0) OR (direction = 'receive' AND source_path IS NULL)),
    CHECK ((stage_name IS NULL AND stage_identity IS NULL AND parent_path IS NULL AND parent_identity IS NULL) OR (direction = 'receive' AND stage_name IS NOT NULL AND parent_path IS NOT NULL AND parent_identity IS NOT NULL)),
    CHECK ((old_identity IS NULL AND old_uid IS NULL AND old_gid IS NULL AND old_mode IS NULL) OR (direction = 'receive' AND mode = 'replace' AND old_identity IS NOT NULL AND old_uid IS NOT NULL AND old_gid IS NOT NULL AND old_mode IS NOT NULL)),
    CHECK (direction = 'send' OR (mode = 'create' AND old_identity IS NULL) OR (mode = 'replace' AND old_identity IS NOT NULL)),
    CHECK (stage_name IS NULL OR (length(stage_name) = 40 AND substr(stage_name, 1, 4) = '.px-' AND substr(stage_name, 37) = '.put' AND substr(stage_name, 5, 32) NOT GLOB '*[^0-9a-f]*')),
    CHECK (parent_synced = 0 OR stage_removed = 1),
    CHECK (stage_removed = 0 OR (direction = 'receive' AND stage_name IS NOT NULL AND state IN ('cleanup_not_attempted','committed'))),
    CHECK (created + replaced <= 1),
    CHECK ((state = 'stage_intent' AND direction = 'receive' AND stage_name IS NOT NULL AND stage_identity IS NULL AND stage_removed = 0 AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'transferring' AND created = 0 AND replaced = 0 AND durability IS NULL AND (direction = 'send' OR (stage_identity IS NOT NULL AND stage_removed = 0)))
        OR (state = 'publication_intent' AND direction = 'receive' AND stage_identity IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'cleanup_not_attempted' AND direction = 'receive' AND stage_name IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL)
        OR (state = 'committed' AND durability IS NOT NULL AND ((mode = 'create' AND created = 1 AND replaced = 0) OR (mode = 'replace' AND created = 0 AND replaced = 1)))
        OR (state = 'outcome_unknown' AND direction = 'receive' AND stage_identity IS NOT NULL AND created = 0 AND replaced = 0 AND durability IS NULL))
);

INSERT INTO put_transfers(direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,parent_path,parent_identity,stage_name,stage_identity,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,acknowledged_bytes,created,replaced,durability,stage_removed,backup_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at)
SELECT direction,transfer_id,protocol_version,context_name,peer_device_id,local_device_id,peer_label,destination,mode,expected_sha256,source_size,source_sha256,chunk_size,ack_window,put_root_revision,source_path,parent_path,parent_identity,stage_name,stage_identity,old_identity,old_uid,old_gid,old_mode,old_metadata,backup_name,backup_identity,backup_size,state,acknowledged_bytes,created,replaced,durability,stage_removed,backup_removed,parent_synced,created_at,updated_at,expires_at,next_retry_at,lease_token,lease_expires_at FROM put_transfers_resolution;
DROP TABLE put_transfers_resolution;
CREATE INDEX put_transfers_context_updated ON put_transfers(context_name, updated_at DESC, direction, transfer_id);
CREATE INDEX put_transfers_due_parent ON put_transfers(parent_path, parent_identity, next_retry_at, created_at, transfer_id);

-- +goose StatementBegin
CREATE TRIGGER put_shared_quota_insert BEFORE INSERT ON put_transfers BEGIN
    SELECT CASE WHEN NEW.direction = 'send' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND (SELECT count(*) FROM transfer_resumes WHERE direction = 'send') + (SELECT count(*) FROM put_transfers WHERE direction = 'send') >= 64 THEN RAISE(ABORT, 'shared sender transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND (SELECT count(*) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) + (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) >= 64 THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) + (SELECT coalesce(sum(source_size + backup_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) > 4294967296 - NEW.source_size - NEW.backup_size THEN RAISE(ABORT, 'shared receiver byte capacity reached') END;
END;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE TRIGGER transfer_shared_quota_insert BEFORE INSERT ON transfer_resumes BEGIN
    SELECT CASE WHEN NEW.direction = 'send' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND (SELECT count(*) FROM transfer_resumes WHERE direction = 'send') + (SELECT count(*) FROM put_transfers WHERE direction = 'send') >= 64 THEN RAISE(ABORT, 'shared sender transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND (SELECT count(*) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) + (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) >= 64 THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) + (SELECT coalesce(sum(source_size + backup_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) > 4294967296 - NEW.source_size THEN RAISE(ABORT, 'shared receiver byte capacity reached') END;
END;
-- +goose StatementEnd
