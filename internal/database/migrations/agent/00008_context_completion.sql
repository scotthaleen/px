-- +goose Up
CREATE INDEX context_alias_completion ON context_aliases(context_name, lower(target_label), alias);
CREATE INDEX transfer_completion ON transfer_resumes(context_name, transfer_id, direction);

-- +goose Down
DROP INDEX transfer_completion;
DROP INDEX context_alias_completion;
