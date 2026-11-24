-- +goose Up
-- +goose StatementBegin
DO $$
BEGIN
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='gatebeam_ca_runtime') THEN
  CREATE ROLE gatebeam_ca_runtime NOLOGIN;
 END IF;
 IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='gatebeam_ca_admin') THEN
  CREATE ROLE gatebeam_ca_admin NOLOGIN;
 END IF;
 EXECUTE format('GRANT USAGE ON SCHEMA %I TO gatebeam_ca_runtime, gatebeam_ca_admin', current_schema());
END;
$$;
-- +goose StatementEnd
GRANT SELECT ON pki_issuers TO gatebeam_ca_admin;
GRANT SELECT, INSERT ON pki_issuers TO gatebeam_ca_runtime;
GRANT INSERT ON pki_serial_reservations TO gatebeam_ca_runtime;
-- Both roles also need USAGE on the deployment schema; grant it using its actual
-- configured name. Neither role receives issuer mutation or private key access.

-- P2 authority split: API writes enrollment policy; CA can only bind accounts
-- to existing policy and consume EAB. Shared advisory principal locks require
-- no UPDATE privilege on principal rows.
GRANT SELECT,INSERT ON pki_principals,pki_grants TO gatebeam_ca_admin;
GRANT UPDATE(disabled) ON pki_principals TO gatebeam_ca_admin;
GRANT SELECT,INSERT ON pki_eab TO gatebeam_ca_admin;
GRANT UPDATE(consumed) ON pki_eab TO gatebeam_ca_admin;
GRANT SELECT ON pki_accounts TO gatebeam_ca_admin;
GRANT SELECT ON pki_principals,pki_grants,pki_eab TO gatebeam_ca_runtime;
GRANT UPDATE(consumed) ON pki_eab TO gatebeam_ca_runtime;
GRANT SELECT,INSERT ON pki_accounts TO gatebeam_ca_runtime;
GRANT UPDATE(thumbprint,public_key,status,contacts,revision) ON pki_accounts TO gatebeam_ca_runtime;
GRANT SELECT,INSERT,DELETE ON pki_nonces TO gatebeam_ca_runtime;

-- P3: only CA can append certificate DER and advance authorized orders.
GRANT SELECT,INSERT ON pki_orders,pki_certificates TO gatebeam_ca_runtime;
GRANT UPDATE(status,challenges,revision) ON pki_orders TO gatebeam_ca_runtime;
GRANT SELECT(order_id,issuer_id,serial,not_before,not_after) ON pki_certificates TO gatebeam_ca_admin;

-- P4: immutable revocation authority is synchronously writable by API and CA.
GRANT SELECT,INSERT ON pki_revocations TO gatebeam_ca_admin,gatebeam_ca_runtime;
GRANT SELECT(id,account_id,names,purpose) ON pki_orders TO gatebeam_ca_admin;
GRANT SELECT,INSERT ON pki_status_certificates,pki_crl_versions TO gatebeam_ca_runtime;
GRANT UPDATE(number) ON pki_crl_versions TO gatebeam_ca_runtime;

GRANT SELECT,INSERT ON pki_root_crl_state TO gatebeam_ca_runtime;
GRANT UPDATE(number,der,revoked_serials) ON pki_root_crl_state TO gatebeam_ca_runtime;

-- All issuer users read quarantine; none may erase it or admit an unsafe issuer.
GRANT SELECT ON pki_restore_quarantine TO gatebeam_ca_runtime,gatebeam_ca_admin;

-- Derived public status; issuer metadata refresh cannot alter DER or signing state.
GRANT UPDATE(key_fingerprint) ON pki_issuers TO gatebeam_ca_runtime;
GRANT SELECT ON pki_eab_envelopes TO gatebeam_ca_runtime;
GRANT INSERT ON audit TO gatebeam_ca_admin;
