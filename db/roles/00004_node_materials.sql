-- +goose Up
-- Historical ciphertext maintenance is a separately granted capability. Normal
-- delivery/issuance/CA logins cannot rewrite credential representations.
-- +goose StatementBegin
DO $rewrap$
DECLARE role_name text; existing record;
BEGIN
 FOREACH role_name IN ARRAY ARRAY['gatebeam_certificate_rewrap','gatebeam_notification_rewrap','gatebeam_pki_rewrap'] LOOP
  SELECT * INTO existing FROM pg_roles WHERE rolname=role_name;
  IF FOUND THEN
   IF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreaterole OR existing.rolcreatedb OR existing.rolreplication OR existing.rolbypassrls
    OR EXISTS(SELECT 1 FROM pg_auth_members WHERE member=existing.oid)
    OR EXISTS(SELECT 1 FROM pg_shdepend WHERE refclassid='pg_authid'::regclass AND refobjid=existing.oid AND deptype='o') THEN
    RAISE EXCEPTION 'Conflicting representation maintenance capability';
   END IF;
  ELSE
   EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS',role_name);
  END IF;
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I',current_schema(),role_name);
 END LOOP;
END $rewrap$;
-- +goose StatementEnd
GRANT SELECT,INSERT ON certificates_node_envelopes TO gatebeam_certificates_edge;
GRANT SELECT ON certificates_node_envelopes TO gatebeam_backup_snapshot;
GRANT SELECT,INSERT,UPDATE,DELETE ON certificates_http_challenges,certificates_http_targets TO gatebeam_certificates_worker;
GRANT SELECT ON certificates_http_challenges,certificates_http_targets TO gatebeam_certificates_edge,gatebeam_backup_snapshot;
GRANT UPDATE(ready) ON certificates_http_targets TO gatebeam_certificates_edge;
GRANT SELECT ON certificates_provider_envelopes TO gatebeam_certificates_management;
GRANT SELECT ON certificates_provider_envelopes TO gatebeam_certificates_worker;
GRANT SELECT ON certificates_revisions,certificates_watermark TO gatebeam_certificate_rewrap;
GRANT UPDATE ON certificates_watermark TO gatebeam_certificate_rewrap;
GRANT SELECT,INSERT,UPDATE ON certificates_provider_envelopes TO gatebeam_certificate_rewrap;
GRANT SELECT ON pki_eab_envelopes TO gatebeam_pki_ca;
GRANT SELECT ON pki_eab TO gatebeam_pki_rewrap;
GRANT UPDATE(consumed) ON pki_eab TO gatebeam_pki_rewrap;
GRANT SELECT,INSERT,UPDATE ON pki_eab_envelopes TO gatebeam_pki_rewrap;
GRANT SELECT ON notification_channels TO gatebeam_notification_rewrap;
GRANT UPDATE(secret) ON notification_channels TO gatebeam_notification_rewrap;
GRANT SELECT ON certificates_provider_envelopes,pki_eab_envelopes TO gatebeam_backup_snapshot;
-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'material capabilities are forward-only'; END $$;
-- +goose StatementEnd
