-- +goose Up
-- deployment owns execution receipts. This row is acknowledged only together
-- with owner ingress publication and the platform job fencing transaction.
ALTER TABLE deployment_releases ADD COLUMN observed_version text NOT NULL DEFAULT '', ADD COLUMN restored_version text NOT NULL DEFAULT '';
CREATE TABLE deployment_runtime(id boolean PRIMARY KEY DEFAULT true CHECK(id),release_id uuid NOT NULL REFERENCES deployment_releases(id),artifact_id text NOT NULL CHECK(length(artifact_id)=64),version text NOT NULL,verified_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- +goose Down
DROP TABLE deployment_runtime;
ALTER TABLE deployment_releases DROP COLUMN observed_version,DROP COLUMN restored_version;
