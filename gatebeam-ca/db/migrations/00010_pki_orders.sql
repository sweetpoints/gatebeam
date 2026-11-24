-- +goose Up
-- PKI-owned issuance records. Only the CA role may write DER and order state.
ALTER TABLE pki_accounts ADD COLUMN revision bigint NOT NULL DEFAULT 1 CHECK(revision>0);
CREATE TABLE pki_orders (
 id text PRIMARY KEY,
 account_id text NOT NULL REFERENCES pki_accounts(id),
 directory text NOT NULL CHECK(directory IN ('server','client')),
 names text[] NOT NULL CHECK(cardinality(names) BETWEEN 1 AND 100),
 purpose text NOT NULL CHECK(purpose IN ('serverAuth','clientAuth')),
 status text NOT NULL CHECK(status IN ('pending','ready','valid','invalid')),
 expires timestamptz NOT NULL,
 challenges jsonb NOT NULL CHECK(jsonb_typeof(challenges)='array'),
 revision bigint NOT NULL CHECK(revision>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX pki_orders_account ON pki_orders(account_id,id);
CREATE TABLE pki_certificates (
 order_id text PRIMARY KEY REFERENCES pki_orders(id),
 issuer_id text NOT NULL,
 serial text NOT NULL,
 der bytea NOT NULL CHECK(octet_length(der) BETWEEN 1 AND 65536),
 chain bytea NOT NULL CHECK(octet_length(chain) BETWEEN 1 AND 262144),
 not_before timestamptz NOT NULL,
 not_after timestamptz NOT NULL CHECK(not_after>not_before),
 UNIQUE(issuer_id,serial),
 FOREIGN KEY(issuer_id,serial) REFERENCES pki_serial_reservations(issuer_id,serial)
);
-- The account revision detects a key changed away and back during HTTP-01.
-- +goose StatementBegin
CREATE FUNCTION pki_guard_account_revision() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.revision<>OLD.revision+1 THEN RAISE EXCEPTION 'invalid account revision'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_account_revision BEFORE UPDATE ON pki_accounts FOR EACH ROW EXECUTE FUNCTION pki_guard_account_revision();
-- +goose StatementBegin
CREATE FUNCTION pki_guard_order() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.id<>OLD.id OR NEW.account_id<>OLD.account_id OR NEW.directory<>OLD.directory OR NEW.names<>OLD.names OR NEW.purpose<>OLD.purpose OR NEW.expires<>OLD.expires OR NEW.revision<>OLD.revision+1 OR OLD.status IN ('valid','invalid') THEN
  RAISE EXCEPTION 'immutable or terminal ACME order';
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_order_immutable BEFORE UPDATE ON pki_orders FOR EACH ROW EXECUTE FUNCTION pki_guard_order();
-- +goose Down
DROP TRIGGER pki_account_revision ON pki_accounts;
DROP FUNCTION pki_guard_account_revision();
DROP TABLE pki_certificates,pki_orders;
DROP FUNCTION pki_guard_order();
ALTER TABLE pki_accounts DROP COLUMN revision;
