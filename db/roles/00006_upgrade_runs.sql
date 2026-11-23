-- +goose Up
GRANT SELECT,INSERT,UPDATE ON deployment_upgrade_runs TO gatebeam_deployment_node_admin;
GRANT SELECT ON deployment_upgrade_runs TO gatebeam_deployment_operations_reader,gatebeam_backup_snapshot;
-- Private CA readiness reads only registered public node recipients.
GRANT SELECT ON deployment_nodes TO gatebeam_pki_ca;
-- Existing role-local ACME clients may publish challenges, never forge an
-- edge acknowledgement: ready is not an INSERT/UPDATE capability here.
GRANT SELECT,INSERT,DELETE ON certificates_http_challenges TO gatebeam_runtime_api,gatebeam_pki_ca;
GRANT UPDATE(retired) ON certificates_http_challenges TO gatebeam_runtime_api,gatebeam_pki_ca;
GRANT SELECT ON certificates_http_targets TO gatebeam_runtime_api,gatebeam_pki_ca;
GRANT INSERT(owner,token,node_id,node_epoch) ON certificates_http_targets TO gatebeam_runtime_api,gatebeam_pki_ca;
-- The role-local shared endpoint publisher is restricted to challenges already
-- authorized by the standard internal ACME service. Parsed SQL bodies bind
-- relation OIDs at creation; caller search_path cannot replace authority tables.
-- +goose StatementBegin
DO $migration$
DECLARE ns text := current_schema();
BEGIN
 EXECUTE format($ddl$
 CREATE OR REPLACE FUNCTION %I.internal_http_challenge_authorized(t text,k text) RETURNS boolean
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog
 BEGIN ATOMIC
 RETURN EXISTS(SELECT 1 FROM %I.pki_orders o JOIN %I.pki_accounts a ON a.id=o.account_id,
 jsonb_array_elements(o.challenges) c WHERE c->>'Token'=t AND k=t||'.'||a.thumbprint);
 END
 $ddl$,ns,ns,ns);
END $migration$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION internal_http_challenge_authorized(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION internal_http_challenge_authorized(text,text) TO gatebeam_runtime_api,gatebeam_pki_ca,gatebeam_certificates_worker;
ALTER TABLE certificates_http_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE certificates_http_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS http_challenges_read ON certificates_http_challenges;
CREATE POLICY http_challenges_read ON certificates_http_challenges FOR SELECT USING(true);
DROP POLICY IF EXISTS http_challenges_insert ON certificates_http_challenges;
CREATE POLICY http_challenges_insert ON certificates_http_challenges FOR INSERT WITH CHECK(
 has_table_privilege(session_user,'certificates_http_challenges'::regclass,'UPDATE') OR internal_http_challenge_authorized(token,key_authorization));
DROP POLICY IF EXISTS http_challenges_update ON certificates_http_challenges;
CREATE POLICY http_challenges_update ON certificates_http_challenges FOR UPDATE USING(
 has_table_privilege(session_user,'certificates_http_challenges'::regclass,'UPDATE') OR internal_http_challenge_authorized(token,key_authorization)) WITH CHECK(
 has_table_privilege(session_user,'certificates_http_challenges'::regclass,'UPDATE') OR internal_http_challenge_authorized(token,key_authorization));
DROP POLICY IF EXISTS http_challenges_delete ON certificates_http_challenges;
CREATE POLICY http_challenges_delete ON certificates_http_challenges FOR DELETE USING(
 has_table_privilege(session_user,'certificates_http_challenges'::regclass,'UPDATE') OR internal_http_challenge_authorized(token,key_authorization));
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'upgrade capabilities are forward-only'; END $$;
-- +goose StatementEnd
