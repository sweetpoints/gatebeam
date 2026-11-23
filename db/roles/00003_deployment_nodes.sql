-- +goose Up
-- +goose StatementBegin
DO $registrar$
DECLARE existing record;
BEGIN
 SELECT * INTO existing FROM pg_roles WHERE rolname='gatebeam_deployment_node_admin';
 IF FOUND THEN
  IF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreaterole OR existing.rolcreatedb OR existing.rolreplication OR existing.rolbypassrls
   OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=existing.oid)
   OR EXISTS(SELECT 1 FROM pg_shdepend WHERE refclassid='pg_authid'::regclass AND refobjid=existing.oid AND deptype='o') THEN
   RAISE EXCEPTION 'Conflicting node registrar capability role';
  END IF;
 ELSE
  CREATE ROLE gatebeam_deployment_node_admin NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
 END IF;
 EXECUTE format('GRANT USAGE ON SCHEMA %I TO gatebeam_deployment_node_admin',current_schema());
END $registrar$;
-- +goose StatementEnd
GRANT SELECT ON deployment_nodes,deployment_desired,deployment_node_runtime,deployment_node_events TO gatebeam_runtime_api,gatebeam_runtime_edge,gatebeam_runtime_worker,gatebeam_deployment_operations_reader,gatebeam_backup_snapshot;
GRANT SELECT,INSERT,UPDATE,DELETE ON deployment_nodes,deployment_desired,deployment_node_runtime,deployment_node_events TO gatebeam_deployment_node_admin;
GRANT SELECT ON deployment_candidates,deployment_releases,deployment_runtime,deployment_generation TO gatebeam_deployment_node_admin;
GRANT UPDATE(id) ON deployment_generation TO gatebeam_deployment_node_admin,gatebeam_runtime_api;
GRANT INSERT ON audit TO gatebeam_deployment_node_admin;
GRANT INSERT,UPDATE ON deployment_desired TO gatebeam_runtime_api;
GRANT INSERT,UPDATE ON deployment_node_runtime,deployment_node_events TO gatebeam_runtime_edge;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'runtime node grants are forward-only'; END $$;
-- +goose StatementEnd
