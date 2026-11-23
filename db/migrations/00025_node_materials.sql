-- +goose Up
CREATE TABLE certificates_node_envelopes (
 version_id uuid NOT NULL REFERENCES certificates_versions(id),
 node_id uuid NOT NULL,node_epoch bigint NOT NULL CHECK(node_epoch>0),
 recipient text NOT NULL CHECK(length(recipient) BETWEEN 1 AND 128),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 1048576),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(version_id,node_id,node_epoch,recipient)
);
CREATE TABLE certificates_http_challenges (
 owner uuid NOT NULL,token text NOT NULL UNIQUE CHECK(length(token) BETWEEN 1 AND 256 AND token ~ '^[A-Za-z0-9_-]+$'),
 key_authorization text NOT NULL CHECK(length(key_authorization) BETWEEN 3 AND 513),
 retired boolean NOT NULL DEFAULT false,
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '5 minutes',
 PRIMARY KEY(owner,token)
);
CREATE TABLE certificates_http_targets (
 owner uuid NOT NULL,token text NOT NULL,node_id uuid NOT NULL,node_epoch bigint NOT NULL CHECK(node_epoch>0),
 ready boolean NOT NULL DEFAULT false,
 PRIMARY KEY(owner,token,node_id,node_epoch),
 FOREIGN KEY(owner,token) REFERENCES certificates_http_challenges(owner,token) ON DELETE CASCADE
);
ALTER TABLE certificates_http_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates_http_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY http_targets_read ON certificates_http_targets FOR SELECT USING(true);
CREATE POLICY http_targets_worker_insert ON certificates_http_targets FOR INSERT WITH CHECK(has_table_privilege(session_user,'certificates_http_challenges'::regclass,'INSERT'));
CREATE POLICY http_targets_node_update ON certificates_http_targets FOR UPDATE USING(
 has_table_privilege(session_user,'certificates_http_challenges'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
) WITH CHECK(
 has_table_privilege(session_user,'certificates_http_challenges'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
);
CREATE POLICY http_targets_worker_delete ON certificates_http_targets FOR DELETE USING(has_table_privilege(session_user,'certificates_http_challenges'::regclass,'DELETE'));
CREATE TABLE certificates_provider_envelopes (
 kind text NOT NULL CHECK(kind IN('account','credential')),id uuid NOT NULL,revision bigint NOT NULL,
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 2097152),
 PRIMARY KEY(kind,id,revision),
 FOREIGN KEY(kind,id,revision) REFERENCES certificates_revisions(kind,id,revision)
);
CREATE TABLE pki_eab_envelopes (
 id text PRIMARY KEY REFERENCES pki_eab(id),
 ciphertext bytea NOT NULL CHECK(octet_length(ciphertext) BETWEEN 1 AND 8192)
);
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'node material distribution is forward-only'; END $$;
-- +goose StatementEnd
