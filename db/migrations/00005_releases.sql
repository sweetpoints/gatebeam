-- +goose Up
-- deployment owns immutable candidates and queue records; no ingress heads advance here.
CREATE TABLE deployment_candidates(id uuid PRIMARY KEY,body jsonb NOT NULL,input_digest text NOT NULL CHECK(length(input_digest)=64),created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE deployment_releases(id uuid PRIMARY KEY REFERENCES deployment_candidates(id),state text NOT NULL DEFAULT 'queued' CHECK(state IN ('queued','preparing','validated','applying','verifying','succeeded','failed','restoring','restored','restore_failed')),created_at timestamptz NOT NULL DEFAULT clock_timestamp());
-- +goose StatementBegin
CREATE FUNCTION deployment_immutable_candidate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable deployment candidate'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER deployment_candidate_immutable BEFORE UPDATE OR DELETE ON deployment_candidates FOR EACH ROW EXECUTE FUNCTION deployment_immutable_candidate();
-- +goose Down
DROP TABLE deployment_releases,deployment_candidates;
DROP FUNCTION deployment_immutable_candidate();
