package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CheckCARole checks authority, not only the current role's ordinary table ACL.
// PG18 has_any_column_privilege includes column grants; pg_has_role USAGE covers
// inherited ownership, and SET follows the session login's transitive SET paths.
// Owners retain DDL and grant options after revoking their own ordinary DML.
// ADMIN can enable new SET paths; server file/program roles bypass table ACLs.
// PG18 semantics: /docs/18/functions-info.html#FUNCTIONS-INFO-ACCESS-TABLE,
// /docs/18/ddl-priv.html, /docs/18/sql-grant.html, /docs/18/predefined-roles.html
// on https://www.postgresql.org.
// Provision roles separately; startup never grants or revokes privileges.
func CheckCARole(ctx context.Context, p *pgxpool.Pool) error {
	var ok bool
	e := p.QueryRow(ctx, `WITH reachable AS (
 SELECT r.* FROM pg_catalog.pg_roles r
 WHERE r.rolname=current_user OR r.rolname=session_user
    OR pg_catalog.pg_has_role(session_user,r.oid,'SET')
), protected AS (
 SELECT c.oid,c.relowner,n.nspowner,c.relname
 FROM pg_catalog.pg_class c
 JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE c.oid IN ('pki_issuers'::pg_catalog.regclass,
                 'pki_serial_reservations'::pg_catalog.regclass,'pki_certificates'::pg_catalog.regclass,'pki_revocations'::pg_catalog.regclass,'pki_status_certificates'::pg_catalog.regclass,'pki_restore_quarantine'::pg_catalog.regclass)
), managed AS (
 SELECT c.oid,c.relowner,n.nspowner,c.relname
 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
 WHERE c.oid IN ('pki_principals'::regclass,'pki_grants'::regclass,'pki_eab'::regclass,'pki_accounts'::regclass,'pki_nonces'::regclass,'pki_orders'::regclass,'pki_crl_versions'::regclass,'pki_root_crl_state'::regclass)
)
SELECT pg_catalog.has_table_privilege(current_user,'pki_restore_quarantine','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_issuers','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_issuers','INSERT')
 AND pg_catalog.has_column_privilege(current_user,'pki_issuers','key_fingerprint','UPDATE')
 AND pg_catalog.has_table_privilege(current_user,'pki_serial_reservations','INSERT')
 AND pg_catalog.has_table_privilege(current_user,'pki_orders','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_orders','INSERT')
 AND pg_catalog.has_table_privilege(current_user,'pki_certificates','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_certificates','INSERT')
 AND pg_catalog.has_table_privilege(current_user,'pki_revocations','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_revocations','INSERT')
 AND pg_catalog.has_table_privilege(current_user,'pki_status_certificates','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_status_certificates','INSERT')
 AND pg_catalog.has_table_privilege(current_user,'pki_crl_versions','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_crl_versions','INSERT')
 AND pg_catalog.has_column_privilege(current_user,'pki_crl_versions','number','UPDATE')
 AND pg_catalog.has_table_privilege(current_user,'pki_root_crl_state','SELECT')
 AND pg_catalog.has_table_privilege(current_user,'pki_root_crl_state','INSERT')
 AND pg_catalog.has_column_privilege(current_user,'pki_root_crl_state','number','UPDATE')
 AND pg_catalog.has_column_privilege(current_user,'pki_root_crl_state','der','UPDATE')
 AND pg_catalog.has_column_privilege(current_user,'pki_root_crl_state','revoked_serials','UPDATE')
 AND NOT EXISTS (
  SELECT 1 FROM reachable r
  WHERE r.rolsuper OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication OR r.rolbypassrls
     OR EXISTS (
      SELECT 1 FROM pg_catalog.pg_roles capability
      WHERE pg_catalog.pg_has_role(r.oid,capability.oid,'MEMBER WITH ADMIN OPTION')
         OR (capability.rolname IN ('pg_read_server_files','pg_write_server_files','pg_execute_server_program')
             AND pg_catalog.pg_has_role(r.oid,capability.oid,'USAGE'))
     )
     OR EXISTS (
      SELECT 1 FROM managed c
      WHERE pg_catalog.pg_has_role(r.oid,c.relowner,'USAGE')
       OR pg_catalog.pg_has_role(r.oid,c.nspowner,'USAGE')
       OR pg_catalog.has_table_privilege(r.oid,c.oid,'TRUNCATE')
       OR (c.relname IN ('pki_principals','pki_grants','pki_eab') AND pg_catalog.has_table_privilege(r.oid,c.oid,'INSERT,DELETE'))
       OR (c.relname IN ('pki_accounts','pki_orders','pki_crl_versions','pki_root_crl_state') AND pg_catalog.has_table_privilege(r.oid,c.oid,'DELETE'))
       OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped
        AND pg_catalog.has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE')
        AND NOT ((c.relname='pki_root_crl_state' AND a.attname IN ('number','der','revoked_serials')) OR (c.relname='pki_crl_versions' AND a.attname='number') OR (c.relname='pki_eab' AND a.attname='consumed') OR (c.relname='pki_accounts' AND a.attname IN ('thumbprint','public_key','status','contacts','revision')) OR (c.relname='pki_orders' AND a.attname IN ('status','challenges','revision'))))
     )
     OR EXISTS (
      SELECT 1 FROM protected c
      WHERE pg_catalog.pg_has_role(r.oid,c.relowner,'USAGE')
         OR pg_catalog.pg_has_role(r.oid,c.nspowner,'USAGE')
         OR EXISTS (SELECT 1 FROM pg_catalog.pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND pg_catalog.has_column_privilege(r.oid,c.oid,a.attnum,'UPDATE') AND NOT (c.relname='pki_issuers' AND a.attname='key_fingerprint'))
         OR pg_catalog.has_table_privilege(r.oid,c.oid,'DELETE,TRUNCATE')
     )
 )`).Scan(&ok)
	if e != nil || !ok {
		return errors.New("CA database role violates issuer immutability or enrollment authority separation")
	}
	return nil
}
