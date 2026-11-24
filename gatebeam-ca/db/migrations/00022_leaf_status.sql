-- +goose Up
-- PKI owns this derived public projection. No DER, account or signing data is exposed.
ALTER TABLE pki_issuers ADD COLUMN key_fingerprint text CHECK(key_fingerprint ~ '^[0-9a-f]{64}$');
-- Public key identity may be completed once, never rebound by the CA role.
-- +goose StatementBegin
CREATE FUNCTION pki_immutable_issuer_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.key_fingerprint IS NOT NULL AND NEW.key_fingerprint IS DISTINCT FROM OLD.key_fingerprint THEN
  RAISE EXCEPTION 'immutable issuer key identity';
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER pki_issuer_key_immutable BEFORE UPDATE OF key_fingerprint ON pki_issuers
 FOR EACH ROW EXECUTE FUNCTION pki_immutable_issuer_key();
CREATE VIEW pki_leaf_status WITH (security_barrier=true) AS
SELECT i.key_fingerprint AS issuer_key_fingerprint, c.serial,
 encode(sha256(c.der),'hex') AS leaf_fingerprint,
 CASE WHEN i.key_fingerprint IS NULL THEN 'unclassified'
      WHEN q.issuer_id IS NOT NULL THEN 'quarantined'
      WHEN r.serial IS NOT NULL THEN 'revoked'
      WHEN c.serial IS NULL THEN 'unknown' ELSE 'good' END AS state
FROM pki_issuers i
LEFT JOIN pki_certificates c ON c.issuer_id=i.id
LEFT JOIN pki_revocations r ON (r.issuer_id,r.serial)=(c.issuer_id,c.serial)
LEFT JOIN pki_restore_quarantine q ON q.issuer_id=i.id;
REVOKE ALL ON pki_leaf_status FROM PUBLIC;
-- +goose Down
DROP VIEW pki_leaf_status;
DROP TRIGGER pki_issuer_key_immutable ON pki_issuers;
DROP FUNCTION pki_immutable_issuer_key();
ALTER TABLE pki_issuers DROP COLUMN key_fingerprint;
