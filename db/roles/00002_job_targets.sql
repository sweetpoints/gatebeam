-- +goose Up
-- Existing table-level grants automatically cover the additive target fields.
-- Operations readers explicitly receive only the extra public execution scope.
GRANT SELECT(target_node_id,target_node_epoch) ON jobs TO gatebeam_deployment_operations_reader;
GRANT UPDATE(key) ON jobs TO gatebeam_runtime_api;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'runtime grants are forward-only'; END $$;
-- +goose StatementEnd
