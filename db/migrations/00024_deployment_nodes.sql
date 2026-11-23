-- +goose Up
CREATE TABLE deployment_nodes (
 id uuid PRIMARY KEY,epoch bigint NOT NULL CHECK(epoch>0),principal name NOT NULL UNIQUE,
 state text NOT NULL DEFAULT 'active' CHECK(state IN('active','quarantined','revoked')),
 enabled boolean NOT NULL DEFAULT false,legacy_origin boolean NOT NULL DEFAULT false,registration jsonb NOT NULL,registered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE UNIQUE INDEX deployment_single_legacy_origin ON deployment_nodes((true)) WHERE legacy_origin;
CREATE TABLE deployment_desired (
 release_id uuid NOT NULL REFERENCES deployment_releases(id),node_id uuid NOT NULL REFERENCES deployment_nodes(id),node_epoch bigint NOT NULL CHECK(node_epoch>0),
 is_current boolean NOT NULL DEFAULT true,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(release_id,node_id,node_epoch)
);
CREATE UNIQUE INDEX deployment_desired_current ON deployment_desired(node_id) WHERE is_current;
CREATE TABLE deployment_node_runtime (
 node_id uuid NOT NULL REFERENCES deployment_nodes(id),node_epoch bigint NOT NULL CHECK(node_epoch>0),release_id uuid NOT NULL REFERENCES deployment_releases(id),
 body jsonb NOT NULL,material_bindings jsonb NOT NULL DEFAULT '[]',observed_at timestamptz NOT NULL,
 PRIMARY KEY(node_id,node_epoch),
 CHECK(coalesce(body->'node'->>'id'=node_id::text AND (body->'node'->>'epoch')::bigint=node_epoch AND body->>'release_id'=release_id::text,false))
);
CREATE TABLE deployment_node_events (
 node_id uuid NOT NULL REFERENCES deployment_nodes(id),node_epoch bigint NOT NULL CHECK(node_epoch>0),release_id uuid NOT NULL REFERENCES deployment_releases(id),
 event_id uuid NOT NULL,body jsonb NOT NULL,material_bindings jsonb NOT NULL DEFAULT '[]',observed_at timestamptz NOT NULL,
 PRIMARY KEY(node_id,node_epoch,release_id,event_id),
 CHECK(coalesce(body->'node'->>'id'=node_id::text AND (body->'node'->>'epoch')::bigint=node_epoch AND body->>'release_id'=release_id::text AND body->>'event_id'=event_id::text,false))
);
CREATE INDEX deployment_node_latest ON deployment_node_events(release_id,node_id,node_epoch,observed_at DESC,event_id);
ALTER TABLE deployment_node_runtime ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployment_node_runtime FORCE ROW LEVEL SECURITY;
ALTER TABLE deployment_node_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE deployment_node_events FORCE ROW LEVEL SECURITY;
CREATE POLICY deployment_runtime_read ON deployment_node_runtime FOR SELECT USING(true);
CREATE POLICY deployment_events_read ON deployment_node_events FOR SELECT USING(true);
CREATE POLICY deployment_runtime_insert ON deployment_node_runtime FOR INSERT WITH CHECK(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
);
CREATE POLICY deployment_runtime_update ON deployment_node_runtime FOR UPDATE USING(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
) WITH CHECK(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
);
CREATE POLICY deployment_events_insert ON deployment_node_events FOR INSERT WITH CHECK(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
);
CREATE POLICY deployment_events_update ON deployment_node_events FOR UPDATE USING(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
) WITH CHECK(
 has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') OR EXISTS(SELECT 1 FROM deployment_nodes n WHERE n.id=node_id AND n.epoch=node_epoch AND n.principal=session_user AND n.state='active')
);
CREATE POLICY deployment_runtime_admin_delete ON deployment_node_runtime FOR DELETE USING(has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT'));
CREATE POLICY deployment_events_admin_delete ON deployment_node_events FOR DELETE USING(has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT'));
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'activated node identities and receipts are forward-only'; END $$;
-- +goose StatementEnd
