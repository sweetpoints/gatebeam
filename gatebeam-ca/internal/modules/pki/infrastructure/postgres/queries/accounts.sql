-- name: AccountByID :one
SELECT id,principal_id,directory,thumbprint,public_key,status,contacts,revision FROM pki_accounts WHERE directory=$1 AND id=$2;
-- name: AccountByKey :one
SELECT id,principal_id,directory,thumbprint,public_key,status,contacts,revision FROM pki_accounts WHERE directory=$1 AND thumbprint=$2;
-- name: LockPrincipal :one
SELECT id,names,purpose,directory,expires,disabled FROM pki_principals WHERE id=$1;
-- name: BindingPrincipal :one
SELECT g.principal_id FROM pki_eab b JOIN pki_grants g ON g.id=b.grant_id WHERE b.id=$1;
-- name: ReadBinding :one
SELECT b.id,g.principal_id,b.cipher,b.expires,b.consumed FROM pki_eab b JOIN pki_grants g ON g.id=b.grant_id WHERE b.id=$1 FOR UPDATE OF b;
-- name: ConsumeBinding :execrows
UPDATE pki_eab SET consumed=true WHERE id=$1 AND NOT consumed;
-- name: InsertAccount :exec
INSERT INTO pki_accounts(id,principal_id,directory,thumbprint,public_key,status,contacts) VALUES($1,$2,$3,$4,$5,$6,$7);
-- name: SaveAccount :exec
UPDATE pki_accounts SET thumbprint=$2,public_key=$3,status=$4,contacts=$5,revision=revision+1 WHERE id=$1;
-- name: CleanupNonces :exec
WITH cleanup_guard AS MATERIALIZED (SELECT pg_try_advisory_xact_lock(hashtextextended('gatebeam-ca/pki/nonce-cleanup',0)) AS locked),
expired AS MATERIALIZED (SELECT digest FROM pki_nonces,cleanup_guard WHERE locked AND expires<clock_timestamp() ORDER BY expires LIMIT 128)
DELETE FROM pki_nonces WHERE digest IN (SELECT digest FROM expired);
-- name: AddNonce :exec
INSERT INTO pki_nonces(digest,expires) VALUES($1,$2);
-- name: ConsumeNonce :execrows
DELETE FROM pki_nonces WHERE digest=$1 AND expires>$2;
-- name: InsertPrincipal :exec
INSERT INTO pki_principals(id,names,purpose,directory,expires,disabled) VALUES($1,$2,$3,$4,$5,$6);
-- name: InsertGrant :exec
INSERT INTO pki_grants(id,principal_id) VALUES($1,$2);
-- name: GrantPrincipal :one
SELECT principal_id FROM pki_grants WHERE id=$1;
-- name: ExpireBindings :exec
UPDATE pki_eab SET consumed=true WHERE grant_id=$1 AND NOT consumed;
-- name: InsertBinding :exec
INSERT INTO pki_eab(id,grant_id,cipher,expires) VALUES($1,$2,$3,$4);
-- name: DisablePrincipal :exec
UPDATE pki_principals SET disabled=true WHERE id=$1;

-- name: LockPrincipalID :exec
SELECT pg_advisory_xact_lock(hashtextextended($1::text,0));
