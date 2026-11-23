-- +goose Up
ALTER TABLE observability_segments ADD COLUMN node_id text NOT NULL DEFAULT 'legacy';
ALTER TABLE observability_batches ADD COLUMN node_id text NOT NULL DEFAULT 'legacy';
ALTER TABLE observability_manifests ADD COLUMN node_id text NOT NULL DEFAULT 'legacy';
ALTER TABLE observability_archive_objects ADD COLUMN node_id text NOT NULL DEFAULT 'legacy';
CREATE INDEX observability_batches_node_pending ON observability_batches(node_id,committed_at,id) WHERE NOT local_cleaned;
CREATE INDEX observability_segments_node ON observability_segments(node_id,physical_id);
ALTER TABLE observability_queries ADD COLUMN coverage text NOT NULL DEFAULT '';
ALTER TABLE observability_queries ADD COLUMN truncated boolean NOT NULL DEFAULT false;
ALTER TABLE observability_queries DROP CONSTRAINT observability_queries_state_check;
ALTER TABLE observability_queries ADD CONSTRAINT observability_queries_state_check CHECK(state IN('queued','running','coordinating','succeeded','failed','cancelled'));
CREATE TABLE observability_query_parts (
 query_id uuid NOT NULL REFERENCES observability_queries(id) ON DELETE CASCADE,
 node_id uuid NOT NULL,node_epoch bigint NOT NULL CHECK(node_epoch>0),
 state text NOT NULL DEFAULT 'queued' CHECK(state IN('queued','running','succeeded','failed','unavailable')),
 objects jsonb NOT NULL DEFAULT '[]',result jsonb,error text NOT NULL DEFAULT '',
 lease uuid,lease_until timestamptz,truncated boolean NOT NULL DEFAULT false,
 PRIMARY KEY(query_id,node_id,node_epoch)
);
CREATE INDEX observability_parts_claim ON observability_query_parts(node_id,node_epoch,state);
ALTER TABLE observability_query_parts ENABLE ROW LEVEL SECURITY;
ALTER TABLE observability_query_parts FORCE ROW LEVEL SECURITY;
CREATE POLICY query_parts_read ON observability_query_parts FOR SELECT USING(true);
CREATE POLICY query_parts_insert ON observability_query_parts FOR INSERT WITH CHECK(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR
 has_table_privilege(session_user,'deployment_desired'::regclass,'INSERT')
);
CREATE POLICY query_parts_update ON observability_query_parts FOR UPDATE USING(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(
 SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.state='active'
 AND n.registration->'RolePrincipals'->>'background-jobs'=session_user)
) WITH CHECK(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(
 SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.state='active'
 AND n.registration->'RolePrincipals'->>'background-jobs'=session_user)
);
CREATE POLICY query_parts_delete ON observability_query_parts FOR DELETE USING(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR
 has_table_privilege(session_user,'deployment_desired'::regclass,'INSERT')
);
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'node log provenance and query ownership are forward-only'; END $$;
-- +goose StatementEnd
