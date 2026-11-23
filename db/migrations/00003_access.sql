-- +goose Up
-- identity owns role, grants and API credentials; ingress resources are referenced by ID only.
ALTER TABLE identity_accounts ADD COLUMN role text NOT NULL DEFAULT 'readonly' CHECK(role IN ('readonly','editor','publisher','admin'));
UPDATE identity_accounts SET role='admin';
CREATE TABLE identity_grants(account_id text NOT NULL REFERENCES identity_accounts(id),kind text NOT NULL CHECK(kind IN ('site','group')),resource_id text NOT NULL,PRIMARY KEY(account_id,kind,resource_id));
CREATE TABLE identity_tokens(id text PRIMARY KEY,account_id text NOT NULL REFERENCES identity_accounts(id),digest text NOT NULL UNIQUE,auth_version bigint NOT NULL,actions text[] NOT NULL,site_ids text[] NOT NULL,expires timestamptz NOT NULL,revoked boolean NOT NULL DEFAULT false);
CREATE INDEX identity_tokens_owner ON identity_tokens(account_id);
-- +goose Down
DROP TABLE identity_tokens,identity_grants;
ALTER TABLE identity_accounts DROP COLUMN role;
