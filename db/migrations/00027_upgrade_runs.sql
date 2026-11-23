-- +goose Up
CREATE TABLE deployment_upgrade_runs (
 id uuid PRIMARY KEY,
 revision bigint NOT NULL CHECK(revision>0),
 owner_instance text NOT NULL,
 state text NOT NULL CHECK(state IN('running','paused','completed','rolled_back','quarantined')),
 document jsonb NOT NULL,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX deployment_one_active_upgrade ON deployment_upgrade_runs((true)) WHERE state IN('running','paused');
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'upgrade operation history is forward-only'; END $$;
-- +goose StatementEnd
