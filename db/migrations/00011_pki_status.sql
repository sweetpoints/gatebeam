-- +goose Up
-- PKI-owned permanent, append-only revocation authority. Both API management
-- and CA's standard revokeCert append; neither may erase or edit a revocation.
CREATE TABLE pki_revocations (
 issuer_id text NOT NULL,
 serial text NOT NULL,
 reason integer NOT NULL CHECK(reason IN (0,1,3,4,5,9)),
 revoked_at timestamptz NOT NULL,
 PRIMARY KEY(issuer_id,serial),
 FOREIGN KEY(issuer_id,serial) REFERENCES pki_certificates(issuer_id,serial)
);
CREATE TABLE pki_crl_versions (
 issuer_id text PRIMARY KEY REFERENCES pki_issuers(id),
 number bigint NOT NULL CHECK(number>0)
);
CREATE TABLE pki_status_certificates (
 issuer_id text NOT NULL,
 serial text NOT NULL,
 certificate_der bytea NOT NULL CHECK(octet_length(certificate_der) BETWEEN 1 AND 65536),
 PRIMARY KEY(issuer_id,serial),
 FOREIGN KEY(issuer_id,serial) REFERENCES pki_serial_reservations(issuer_id,serial)
);
CREATE TABLE pki_root_crl_state (
 issuer_id text PRIMARY KEY REFERENCES pki_issuers(id),
 number bigint NOT NULL CHECK(number>0),
 der bytea NOT NULL CHECK(octet_length(der) BETWEEN 1 AND 1048576),
 revoked_serials text[] NOT NULL
);
-- +goose StatementBegin
CREATE FUNCTION pki_guard_root_crl() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.issuer_id<>OLD.issuer_id OR NEW.number<OLD.number OR NOT(OLD.revoked_serials <@ NEW.revoked_serials) OR (NEW.number=OLD.number AND NEW.der<>OLD.der) THEN RAISE EXCEPTION 'root CRL rollback'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_root_crl_monotonic BEFORE UPDATE ON pki_root_crl_state FOR EACH ROW EXECUTE FUNCTION pki_guard_root_crl();
-- +goose StatementBegin
CREATE FUNCTION pki_guard_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 RAISE EXCEPTION 'permanent revocation cannot be changed';
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_revocation_immutable BEFORE UPDATE OR DELETE ON pki_revocations FOR EACH ROW EXECUTE FUNCTION pki_guard_revocation();
-- +goose StatementBegin
CREATE FUNCTION pki_guard_crl_version() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.issuer_id<>OLD.issuer_id OR NEW.number<>OLD.number+1 THEN RAISE EXCEPTION 'invalid CRL version'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_crl_monotonic BEFORE UPDATE ON pki_crl_versions FOR EACH ROW EXECUTE FUNCTION pki_guard_crl_version();
-- +goose Down
DROP TABLE pki_revocations,pki_crl_versions,pki_status_certificates,pki_root_crl_state;
DROP FUNCTION pki_guard_revocation(),pki_guard_crl_version(),pki_guard_root_crl();
