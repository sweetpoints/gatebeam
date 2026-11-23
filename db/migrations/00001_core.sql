-- +goose Up
-- Platform-owned persistence only.
CREATE TABLE jobs (
 id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
 kind text NOT NULL CHECK (kind <> ''), key text NOT NULL CHECK (key <> ''),
 payload jsonb NOT NULL, status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','completed','failed')),
 lease_token text, deadline timestamptz, worker text,
 attempt integer NOT NULL DEFAULT 0 CHECK(attempt>=0), max_attempts integer NOT NULL DEFAULT 5 CHECK(max_attempts>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(kind,key)
);
CREATE INDEX jobs_claim ON jobs(status,created_at);
CREATE TABLE job_attempts (
 job_id text NOT NULL REFERENCES jobs(id), attempt integer NOT NULL, lease_token text NOT NULL UNIQUE,
 worker text NOT NULL, started_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 PRIMARY KEY(job_id,attempt)
);
CREATE TABLE audit (id text PRIMARY KEY, action text NOT NULL CHECK(action<>''), actor_id text NOT NULL, occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), payload jsonb NOT NULL);
CREATE TABLE outbox (event_id text PRIMARY KEY, event_type text NOT NULL CHECK(event_type<>''), schema_version integer NOT NULL CHECK(schema_version>0), aggregate_id text NOT NULL, aggregate_version bigint NOT NULL CHECK(aggregate_version>0), occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(), payload jsonb NOT NULL);
CREATE TABLE consumer_receipts (consumer text NOT NULL, event_id text NOT NULL, processed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(consumer,event_id));
-- +goose Down
DROP TABLE consumer_receipts, outbox, audit, job_attempts, jobs;
