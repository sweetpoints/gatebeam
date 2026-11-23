-- name: CertificateOwner :one
SELECT a.principal_id,a.id AS account_id,a.directory,c.order_id,o.names FROM pki_certificates c JOIN pki_orders o ON o.id=c.order_id JOIN pki_accounts a ON a.id=o.account_id WHERE c.issuer_id=$1 AND c.serial=$2;
-- name: CertificateStatus :one
SELECT r.reason,r.revoked_at FROM pki_certificates c LEFT JOIN pki_revocations r ON (r.issuer_id,r.serial)=(c.issuer_id,c.serial) WHERE c.issuer_id=$1 AND c.serial=$2;
-- name: InsertRevocation :execrows
INSERT INTO pki_revocations(issuer_id,serial,reason,revoked_at) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING;
-- name: NextCRLNumber :one
INSERT INTO pki_crl_versions(issuer_id,number) VALUES($1,1) ON CONFLICT(issuer_id) DO UPDATE SET number=pki_crl_versions.number+1 RETURNING number;
-- name: ListRevocations :many
SELECT serial,reason,revoked_at FROM pki_revocations WHERE issuer_id=$1 ORDER BY serial;

-- name: ReadResponder :one
SELECT certificate_der FROM pki_status_certificates WHERE issuer_id=$1 AND serial=$2;
-- name: InsertResponder :exec
INSERT INTO pki_status_certificates(issuer_id,serial,certificate_der) VALUES($1,$2,$3);
-- name: CurrentAuthorizedNames :many
SELECT DISTINCT (proof->>'Name')::text AS name FROM pki_orders o, jsonb_array_elements(o.challenges) AS proof
WHERE o.account_id=$1 AND o.status IN ('pending','ready','valid') AND o.expires>$2
AND proof->>'Status'='valid';
-- name: IssuerDER :one
SELECT certificate_der FROM pki_issuers WHERE id=$1;

-- name: AcceptRootCRL :execrows
INSERT INTO pki_root_crl_state(issuer_id,number,der,revoked_serials) VALUES($1,$2,$3,$4)
ON CONFLICT(issuer_id) DO UPDATE SET number=EXCLUDED.number,der=EXCLUDED.der,revoked_serials=EXCLUDED.revoked_serials
WHERE pki_root_crl_state.revoked_serials <@ EXCLUDED.revoked_serials AND (EXCLUDED.number>pki_root_crl_state.number OR (EXCLUDED.number=pki_root_crl_state.number AND EXCLUDED.der=pki_root_crl_state.der));
