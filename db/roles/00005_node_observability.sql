-- +goose Up
GRANT SELECT,INSERT,UPDATE,DELETE ON observability_query_parts TO gatebeam_observability_worker,gatebeam_observability_query_api;
GRANT SELECT ON observability_query_parts TO gatebeam_backup_snapshot;
GRANT UPDATE(coverage,truncated) ON observability_queries TO gatebeam_observability_query_api;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'node log capabilities are forward-only'; END $$;
-- +goose StatementEnd
