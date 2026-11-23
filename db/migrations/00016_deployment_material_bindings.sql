-- +goose Up
-- deployment owns the exact public material metadata confirmed by native apply.
ALTER TABLE deployment_runtime ADD COLUMN material_bindings jsonb NOT NULL DEFAULT '[]';
-- +goose Down
ALTER TABLE deployment_runtime DROP COLUMN material_bindings;
