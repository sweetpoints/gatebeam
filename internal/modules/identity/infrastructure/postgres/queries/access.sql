-- name: ReadIdentityWatermark :exec
SELECT id FROM identity_watermark WHERE id=1 FOR SHARE;
-- name: CurrentAccount :one
SELECT * FROM identity_accounts WHERE id=$1;
-- name: SessionByID :one
SELECT * FROM identity_sessions WHERE id=$1;
-- name: TokenByID :one
SELECT * FROM identity_tokens WHERE id=$1;
-- name: TokenByDigest :one
SELECT * FROM identity_tokens WHERE digest=$1;
-- name: CreateToken :exec
INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires,revoked) VALUES($1,$2,$3,$4,$5,$6,$7,$8);
-- name: RevokeToken :execrows
UPDATE identity_tokens SET revoked=true WHERE id=$1;
-- name: Grants :many
SELECT * FROM identity_grants WHERE account_id=$1 ORDER BY kind,resource_id;
-- name: ClearGrants :exec
DELETE FROM identity_grants WHERE account_id=$1;
-- name: AddGrant :exec
INSERT INTO identity_grants(account_id,kind,resource_id) VALUES($1,$2,$3);
-- name: ChangeRole :exec
UPDATE identity_accounts SET role=$2 WHERE id=$1;
-- name: ListAccounts :many
SELECT id,name,state,role,auth_version FROM identity_accounts ORDER BY id LIMIT $1 OFFSET $2;
-- name: ListTokens :many
SELECT * FROM identity_tokens WHERE account_id=$1 ORDER BY id LIMIT $2 OFFSET $3;
