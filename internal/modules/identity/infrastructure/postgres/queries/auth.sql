-- name: LockIdentity :exec
SELECT id FROM identity_watermark WHERE id=1 FOR UPDATE;
-- name: EmptyAccounts :one
SELECT NOT EXISTS(SELECT 1 FROM identity_accounts);
-- name: AccountByName :one
SELECT * FROM identity_accounts WHERE name=$1 FOR UPDATE;
-- name: AccountByID :one
SELECT * FROM identity_accounts WHERE id=$1 FOR UPDATE;
-- name: AccountByInvite :one
SELECT * FROM identity_accounts WHERE invite_hash=$1 AND invite_hash<>'' FOR UPDATE;
-- name: CreateAccount :exec
INSERT INTO identity_accounts(id,name,password_hash,state,auth_version,last_step,seed,invite_hash,invite_expires,failures,locked_until,role) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12);
-- name: SaveAccount :exec
UPDATE identity_accounts SET password_hash=$2,state=$3,auth_version=$4,last_step=$5,seed=$6,invite_hash=$7,invite_expires=$8,failures=$9,locked_until=$10 WHERE id=$1;
-- name: SaveChallenge :exec
INSERT INTO identity_challenges(hash,account_id,auth_version,expires,attempts,consumed) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(hash) DO UPDATE SET attempts=excluded.attempts,consumed=excluded.consumed;
-- name: Challenge :one
SELECT * FROM identity_challenges WHERE hash=$1 FOR UPDATE;
-- name: CreateSession :exec
INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires,revoked) VALUES($1,$2,$3,$4,$5,$6,$7);
-- name: Session :one
SELECT * FROM identity_sessions WHERE token_hash=$1 FOR UPDATE;
-- name: RevokeSession :exec
UPDATE identity_sessions SET revoked=true WHERE id=$1;
-- name: ClearRecovery :exec
DELETE FROM identity_recovery WHERE account_id=$1;
-- name: AddRecovery :exec
INSERT INTO identity_recovery(account_id,hash) VALUES($1,$2);
-- name: ConsumeRecovery :execrows
UPDATE identity_recovery SET consumed=true WHERE account_id=$1 AND hash=$2 AND consumed=false;
