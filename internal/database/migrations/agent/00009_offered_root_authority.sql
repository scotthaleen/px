-- +goose Up
ALTER TABLE contexts ADD COLUMN offered_root_scope TEXT NOT NULL DEFAULT 'narrow' CHECK (offered_root_scope IN ('narrow', 'filesystem-root'));
ALTER TABLE contexts ADD COLUMN offered_root_revision INTEGER NOT NULL DEFAULT 1 CHECK (offered_root_revision > 0);
ALTER TABLE contexts ADD COLUMN filesystem_root_acknowledged INTEGER NOT NULL DEFAULT 0 CHECK (filesystem_root_acknowledged IN (0, 1));
ALTER TABLE transfer_resumes ADD COLUMN offered_root_revision INTEGER CHECK (offered_root_revision > 0);
UPDATE transfer_resumes
SET offered_root_revision = (
    SELECT contexts.offered_root_revision
    FROM contexts
    WHERE contexts.name = transfer_resumes.context_name
)
WHERE direction = 'receive' AND visibility = 'public';

-- +goose Down
ALTER TABLE transfer_resumes DROP COLUMN offered_root_revision;
ALTER TABLE contexts DROP COLUMN filesystem_root_acknowledged;
ALTER TABLE contexts DROP COLUMN offered_root_revision;
ALTER TABLE contexts DROP COLUMN offered_root_scope;
