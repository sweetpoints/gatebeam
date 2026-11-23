-- +goose Up
-- PKI-owned enrollment authority. API writes principal/grant/binding state;
-- CA writes accounts/nonces and may only consume existing binding credentials.
CREATE TABLE pki_principals (
 id text PRIMARY KEY,
 names text[] NOT NULL CHECK(cardinality(names) BETWEEN 1 AND 100),
 purpose text NOT NULL CHECK(purpose IN ('serverAuth','clientAuth')),
 directory text NOT NULL CHECK(directory IN ('server','client')),
 expires timestamptz NOT NULL,
 disabled boolean NOT NULL DEFAULT false,
 CHECK((purpose='serverAuth' AND directory='server') OR (purpose='clientAuth' AND directory='client'))
);
CREATE TABLE pki_grants (
 id text PRIMARY KEY,
 principal_id text NOT NULL REFERENCES pki_principals(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE pki_eab (
 id text PRIMARY KEY,
 grant_id text NOT NULL REFERENCES pki_grants(id),
 cipher bytea NOT NULL CHECK(octet_length(cipher) BETWEEN 1 AND 8192),
 expires timestamptz NOT NULL,
 consumed boolean NOT NULL DEFAULT false
);
CREATE INDEX pki_eab_grant ON pki_eab(grant_id);
CREATE TABLE pki_accounts (
 id text PRIMARY KEY,
 principal_id text NOT NULL REFERENCES pki_principals(id),
 directory text NOT NULL CHECK(directory IN ('server','client')),
 thumbprint text NOT NULL,
 public_key bytea NOT NULL CHECK(octet_length(public_key) BETWEEN 1 AND 8192),
 status text NOT NULL CHECK(status IN ('valid','deactivated')),
 contacts text[] NOT NULL DEFAULT '{}',
 UNIQUE(directory,thumbprint),
 UNIQUE(principal_id,directory)
);
CREATE TABLE pki_nonces (
 digest text PRIMARY KEY,
 expires timestamptz NOT NULL
);
CREATE INDEX pki_nonces_expiry ON pki_nonces(expires);
-- Binding consumption is monotonic even for a role with UPDATE(consumed).
-- Immutable binding metadata prevents a consumed credential being rebound.
-- +goose StatementBegin
CREATE FUNCTION pki_guard_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (OLD.consumed AND NOT NEW.consumed) OR NEW.id<>OLD.id OR NEW.grant_id<>OLD.grant_id OR NEW.cipher<>OLD.cipher OR NEW.expires<>OLD.expires THEN
  RAISE EXCEPTION 'immutable or consumed external binding';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_binding_immutable BEFORE UPDATE ON pki_eab FOR EACH ROW EXECUTE FUNCTION pki_guard_binding();
-- +goose Down
DROP TABLE pki_nonces,pki_accounts,pki_eab,pki_grants,pki_principals;
DROP FUNCTION pki_guard_binding();
