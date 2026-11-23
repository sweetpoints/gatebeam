-- +goose Up
-- deployment owns immutable post-apply evidence, including failed candidates.
-- Current evidence is selected by the current artifact/version, never latest time alone.
CREATE TABLE deployment_route_verifications (
 artifact_id text NOT NULL CHECK(length(artifact_id)=64),
 version text NOT NULL,
 generation text NOT NULL,
 checked_at timestamptz NOT NULL,
 body jsonb NOT NULL,
 PRIMARY KEY(artifact_id,version,generation,checked_at)
);
-- +goose Down
DROP TABLE deployment_route_verifications;
