-- +goose Up
ALTER TABLE jobs ADD COLUMN target_node_id uuid, ADD COLUMN target_node_epoch bigint;
ALTER TABLE jobs ADD CONSTRAINT jobs_target_binding CHECK (
 (target_node_id IS NULL AND target_node_epoch IS NULL AND kind !~ '\.node\..+\.v[0-9]+$') OR
 (target_node_id IS NOT NULL AND target_node_id <> '00000000-0000-0000-0000-000000000000'::uuid AND target_node_epoch IS NOT NULL AND target_node_epoch>0 AND kind ~ '\.node\..+\.v[1-9][0-9]*$')
);
CREATE INDEX jobs_target_claim ON jobs(target_node_id,target_node_epoch,kind,status,created_at,id) WHERE target_node_id IS NOT NULL;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'job target activation is forward-only; use the compatible bridge binary'; END $$;
-- +goose StatementEnd
