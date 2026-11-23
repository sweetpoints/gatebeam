-- +goose Up
-- Observability owns query cancellation, deployment owns sanitized execution metadata.
ALTER TABLE observability_queries DROP CONSTRAINT observability_queries_state_check;
ALTER TABLE observability_queries ADD CHECK(state IN ('queued','running','succeeded','failed','cancelled'));
CREATE TABLE deployment_execution_reports(release_id uuid PRIMARY KEY REFERENCES deployment_releases(id),stage text NOT NULL,cause text NOT NULL,updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- +goose Down
DROP TABLE deployment_execution_reports;
UPDATE observability_queries SET state='failed',error='query_failed' WHERE state='cancelled';
ALTER TABLE observability_queries DROP CONSTRAINT observability_queries_state_check;
ALTER TABLE observability_queries ADD CHECK(state IN ('queued','running','succeeded','failed'));
