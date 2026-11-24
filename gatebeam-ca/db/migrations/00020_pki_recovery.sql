-- +goose Up
CREATE TABLE pki_restore_quarantine(issuer_id text PRIMARY KEY REFERENCES pki_issuers(id),reason text NOT NULL CHECK(reason='unproved_security_watermark'));
CREATE TRIGGER pki_quarantine_permanent BEFORE UPDATE OR DELETE ON pki_restore_quarantine FOR EACH ROW EXECUTE FUNCTION pki_guard_revocation();
-- +goose StatementBegin
CREATE FUNCTION pki_reject_quarantined_issuer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM pki_restore_quarantine WHERE issuer_id=NEW.issuer_id) THEN RAISE EXCEPTION 'issuer quarantined after recovery'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER pki_quarantined_serial BEFORE INSERT ON pki_serial_reservations FOR EACH ROW EXECUTE FUNCTION pki_reject_quarantined_issuer();
-- +goose Down
DROP TRIGGER pki_quarantined_serial ON pki_serial_reservations;
DROP FUNCTION pki_reject_quarantined_issuer();
DROP TABLE pki_restore_quarantine;
