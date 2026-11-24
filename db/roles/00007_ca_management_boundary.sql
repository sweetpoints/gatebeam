-- +goose Up
-- Remove the gateway's enrollment and revocation authority in this schema.
REVOKE ALL PRIVILEGES ON pki_issuers, pki_principals, pki_grants, pki_eab,
 pki_accounts, pki_certificates, pki_orders, pki_revocations,
 pki_restore_quarantine FROM gatebeam_pki_management;
REVOKE UPDATE(disabled) ON pki_principals FROM gatebeam_pki_management;
REVOKE UPDATE(consumed) ON pki_eab FROM gatebeam_pki_management;
REVOKE SELECT(order_id,issuer_id,serial,not_before,not_after) ON pki_certificates FROM gatebeam_pki_management;
REVOKE SELECT(id,account_id,names,purpose) ON pki_orders FROM gatebeam_pki_management;

-- +goose Down
-- +goose StatementBegin
DO $$ BEGIN RAISE EXCEPTION 'CA management capabilities are forward-only'; END $$;
-- +goose StatementEnd
