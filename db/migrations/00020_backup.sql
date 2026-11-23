-- +goose Up
-- Backup owns only delivery receipts, never cross-owner security state.
CREATE TABLE backup_runs(id text PRIMARY KEY CHECK(length(id)=64),created_at timestamptz NOT NULL,manifest jsonb NOT NULL,cipher_sha256 text NOT NULL CHECK(length(cipher_sha256)=64),bytes bigint NOT NULL CHECK(bytes>0));
-- Identity owns this one-shot local rebootstrap gate. Runtime authorization
-- cannot set it; only isolated offline recovery enables it.
CREATE TABLE identity_restore_bootstrap(singleton boolean PRIMARY KEY CHECK(singleton),available boolean NOT NULL);
INSERT INTO identity_restore_bootstrap VALUES(true,false);
-- PKI quarantine is permanent for an issuer whose latest state is unproved.
-- It deliberately cannot be removed by merely supplying a newer timestamp.
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
DROP TABLE pki_restore_quarantine,identity_restore_bootstrap,backup_runs;
