-- name: RegisterIssuer :execrows
INSERT INTO pki_issuers (id,fingerprint,certificate_der,not_before,not_after)
VALUES ($1,$2,$3,$4,$5) ON CONFLICT (id) DO NOTHING;

-- name: ReadIssuer :one
SELECT id,fingerprint,certificate_der,not_before,not_after FROM pki_issuers WHERE id=$1;

-- name: ReserveSerial :exec
INSERT INTO pki_serial_reservations (issuer_id,serial) VALUES ($1,$2);

-- name: EnrollmentMetadata :many
SELECT g.id AS grant_id,p.id AS principal_id,p.names,p.purpose,p.directory,p.expires,p.disabled,
 CASE WHEN e.id IS NULL THEN 'not_issued' WHEN e.consumed THEN 'consumed' WHEN e.expires<=clock_timestamp() THEN 'expired' ELSE 'available' END::text AS binding_state,
 e.expires AS binding_expires
FROM pki_grants g JOIN pki_principals p ON p.id=g.principal_id
LEFT JOIN LATERAL (SELECT id,consumed,expires FROM pki_eab WHERE grant_id=g.id ORDER BY consumed ASC,expires DESC,id DESC LIMIT 1) e ON true
ORDER BY p.id LIMIT 1000;
-- name: IssuedMetadata :many
SELECT c.issuer_id,c.serial,a.principal_id,o.names,o.purpose,c.not_before,c.not_after,r.revoked_at,r.reason
FROM pki_certificates c JOIN pki_orders o ON o.id=c.order_id JOIN pki_accounts a ON a.id=o.account_id
LEFT JOIN pki_revocations r ON r.issuer_id=c.issuer_id AND r.serial=c.serial
ORDER BY c.not_after DESC,c.issuer_id,c.serial LIMIT 1000;
