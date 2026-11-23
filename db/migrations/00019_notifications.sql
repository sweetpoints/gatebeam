-- +goose Up
-- Notification context owns channels, incidents, transitions and delivery state.
CREATE TABLE notification_channels (
 id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
 owner_id text NOT NULL, revision bigint NOT NULL CHECK(revision>0),
 enabled boolean NOT NULL, metadata jsonb NOT NULL, secret bytea NOT NULL
);
CREATE TABLE notification_incidents (
 fingerprint text PRIMARY KEY, source_version bigint NOT NULL,
 state text NOT NULL CHECK(state IN ('firing','resolved')), event jsonb NOT NULL
);
CREATE TABLE notification_transitions (
 id text PRIMARY KEY, fingerprint text NOT NULL REFERENCES notification_incidents,
 event jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE notification_deliveries (
 id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
 transition_id text NOT NULL REFERENCES notification_transitions,
 channel_id text NOT NULL REFERENCES notification_channels,
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','sending','sent','disabled','denied','no_recipient','failed')),
 attempt integer NOT NULL DEFAULT 0,
 next_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_token text, deadline timestamptz, reason text NOT NULL DEFAULT '',
 UNIQUE(transition_id,channel_id)
);
CREATE TABLE notification_attempts (
 delivery_id text NOT NULL REFERENCES notification_deliveries, attempt integer NOT NULL,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz,
 result text NOT NULL DEFAULT 'in_flight', PRIMARY KEY(delivery_id,attempt)
);
CREATE INDEX notification_due ON notification_deliveries(status,next_at);
-- deployment owns monotonic notification source outcomes.
CREATE TABLE deployment_alert_outcomes (kind text NOT NULL, resource_id text NOT NULL, fingerprint text NOT NULL, version bigint NOT NULL, state text NOT NULL, PRIMARY KEY(kind,resource_id,fingerprint));
-- certificates owns monotonic notification source outcomes.
CREATE TABLE certificates_alert_outcomes (kind text NOT NULL, resource_id text NOT NULL, fingerprint text NOT NULL, version bigint NOT NULL, state text NOT NULL, PRIMARY KEY(kind,resource_id,fingerprint));
-- observability owns monotonic notification source outcomes.
CREATE TABLE observability_alert_outcomes (kind text NOT NULL, resource_id text NOT NULL, fingerprint text NOT NULL, version bigint NOT NULL, state text NOT NULL, PRIMARY KEY(kind,resource_id,fingerprint));
-- +goose Down
DROP TABLE deployment_alert_outcomes,certificates_alert_outcomes,observability_alert_outcomes;
DROP TABLE notification_attempts,notification_deliveries,notification_transitions,notification_incidents,notification_channels;
