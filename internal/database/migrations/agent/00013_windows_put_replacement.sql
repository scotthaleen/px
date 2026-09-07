-- +goose Up
DROP TRIGGER transfer_shared_quota_insert;
DROP TRIGGER put_shared_quota_insert;

ALTER TABLE put_transfers ADD COLUMN backup_name TEXT
    CHECK (backup_name IS NULL OR (direction = 'receive' AND mode = 'replace' AND length(backup_name) = 40
        AND substr(backup_name, 1, 4) = '.px-' AND substr(backup_name, 37) = '.bak'
        AND substr(backup_name, 5, 32) NOT GLOB '*[^0-9a-f]*'));
ALTER TABLE put_transfers ADD COLUMN backup_identity TEXT
    CHECK (backup_identity IS NULL OR (direction = 'receive' AND mode = 'replace' AND length(backup_identity) BETWEEN 8 AND 160));
ALTER TABLE put_transfers ADD COLUMN old_metadata TEXT
    CHECK (old_metadata IS NULL OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL
        AND length(old_metadata) BETWEEN 16 AND 160));
ALTER TABLE put_transfers ADD COLUMN backup_size INTEGER NOT NULL DEFAULT 0
    CHECK ((backup_name IS NULL AND backup_identity IS NULL AND backup_size = 0)
        OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL AND backup_identity IS NOT NULL
            AND old_metadata IS NOT NULL AND backup_size BETWEEN 0 AND 4294967296));
ALTER TABLE put_transfers ADD COLUMN backup_removed INTEGER NOT NULL DEFAULT 0
    CHECK (backup_removed IN (0, 1)
        AND (backup_removed = 0 OR (direction = 'receive' AND mode = 'replace' AND backup_name IS NOT NULL
            AND state IN ('cleanup_not_attempted', 'committed')))
        AND (parent_synced = 0 OR backup_name IS NULL OR backup_removed = 1));

-- +goose StatementBegin
CREATE TRIGGER put_shared_quota_insert BEFORE INSERT ON put_transfers BEGIN
    SELECT CASE WHEN NEW.direction = 'send' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'send') +
        (SELECT count(*) FROM put_transfers WHERE direction = 'send') >= 64
        THEN RAISE(ABORT, 'shared sender transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) >= 64
        THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT coalesce(sum(source_size + backup_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) > 4294967296 - NEW.source_size - NEW.backup_size
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
        (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) >= 64
        THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT coalesce(sum(source_size + backup_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL OR backup_identity IS NOT NULL)) > 4294967296 - NEW.source_size
        THEN RAISE(ABORT, 'shared receiver byte capacity reached') END;
END;
-- +goose StatementEnd

-- +goose Down
CREATE TEMP TABLE windows_put_replacement_rollback_guard(value INTEGER CHECK (value = 0));
INSERT INTO windows_put_replacement_rollback_guard
SELECT count(*) FROM put_transfers WHERE backup_name IS NOT NULL OR backup_identity IS NOT NULL OR old_metadata IS NOT NULL OR backup_size != 0 OR backup_removed != 0;
DROP TABLE windows_put_replacement_rollback_guard;
DROP TRIGGER transfer_shared_quota_insert;
DROP TRIGGER put_shared_quota_insert;
ALTER TABLE put_transfers DROP COLUMN backup_removed;
ALTER TABLE put_transfers DROP COLUMN backup_size;
ALTER TABLE put_transfers DROP COLUMN backup_identity;
ALTER TABLE put_transfers DROP COLUMN old_metadata;
ALTER TABLE put_transfers DROP COLUMN backup_name;

-- +goose StatementBegin
CREATE TRIGGER put_shared_quota_insert BEFORE INSERT ON put_transfers BEGIN
    SELECT CASE WHEN NEW.direction = 'send' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'send') +
        (SELECT count(*) FROM put_transfers WHERE direction = 'send') >= 64
        THEN RAISE(ABORT, 'shared sender transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT count(*) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL)) >= 64
        THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM put_transfers WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT coalesce(sum(source_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL)) > 4294967296 - NEW.source_size
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
        (SELECT count(*) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL)) >= 64
        THEN RAISE(ABORT, 'shared receiver transfer capacity reached') END;
    SELECT CASE WHEN NEW.direction = 'receive' AND NOT EXISTS (SELECT 1 FROM transfer_resumes WHERE direction=NEW.direction AND transfer_id=NEW.transfer_id) AND
        (SELECT coalesce(sum(source_size), 0) FROM transfer_resumes WHERE direction = 'receive' AND state IN ('transferring','committing','committed_pending_confirmation')) +
        (SELECT coalesce(sum(source_size), 0) FROM put_transfers WHERE direction = 'receive' AND (state != 'committed' OR stage_identity IS NOT NULL)) > 4294967296 - NEW.source_size
        THEN RAISE(ABORT, 'shared receiver byte capacity reached') END;
END;
-- +goose StatementEnd
