-- +goose Up
-- identity owns all tables in this migration. The watermark orders future F4 authorization.
CREATE TABLE identity_watermark(id integer PRIMARY KEY CHECK(id=1));
INSERT INTO identity_watermark VALUES(1);
CREATE TABLE identity_accounts(
 id text PRIMARY KEY, name text NOT NULL UNIQUE CHECK(length(name) BETWEEN 1 AND 128),
 password_hash text NOT NULL DEFAULT '', state text NOT NULL CHECK(state IN ('pending','active','disabled')),
 auth_version bigint NOT NULL CHECK(auth_version>0), last_step bigint NOT NULL DEFAULT -1,
 seed bytea NOT NULL,invite_hash text NOT NULL DEFAULT '',invite_expires timestamptz NOT NULL,
 failures integer NOT NULL DEFAULT 0 CHECK(failures>=0),locked_until timestamptz NOT NULL
);
CREATE UNIQUE INDEX identity_invite ON identity_accounts(invite_hash) WHERE invite_hash<>'';
CREATE TABLE identity_challenges(hash text PRIMARY KEY,account_id text NOT NULL REFERENCES identity_accounts(id),auth_version bigint NOT NULL,expires timestamptz NOT NULL,attempts integer NOT NULL CHECK(attempts>=0),consumed boolean NOT NULL);
CREATE INDEX identity_challenges_expiry ON identity_challenges(expires);
CREATE TABLE identity_sessions(id text PRIMARY KEY,account_id text NOT NULL REFERENCES identity_accounts(id),token_hash text NOT NULL UNIQUE,csrf_hash text NOT NULL,auth_version bigint NOT NULL,expires timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false);
CREATE INDEX identity_sessions_account ON identity_sessions(account_id);
CREATE TABLE identity_recovery(account_id text NOT NULL REFERENCES identity_accounts(id),hash text NOT NULL,consumed boolean NOT NULL DEFAULT false,PRIMARY KEY(account_id,hash));
-- +goose Down
DROP TABLE identity_recovery,identity_sessions,identity_challenges,identity_accounts,identity_watermark;
