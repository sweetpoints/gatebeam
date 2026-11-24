-- +goose Up
CREATE TABLE audit (id text PRIMARY KEY, action text NOT NULL CHECK(action<>''), actor_id text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), payload jsonb NOT NULL);
-- +goose Down
DROP TABLE audit;
