-- +goose Up
-- Revision-specific history/backoff remains immutable. Issuance exclusion is
-- spec-wide, including concurrently referenced published/current revisions.
CREATE TABLE certificates_issuance_leases(spec_id uuid PRIMARY KEY,revision bigint NOT NULL DEFAULT 0,token text NOT NULL DEFAULT '',lease_until timestamptz NOT NULL DEFAULT '-infinity');
-- Fail closed across an upgrade with old revision-scoped operations in flight.
-- They cannot commit under the new token fence; preparation resumes on expiry.
INSERT INTO certificates_issuance_leases(spec_id,token,lease_until)
 SELECT spec_id,'migration-fence',max(lease_until) FROM certificates_attempts
 WHERE lease_until>clock_timestamp() GROUP BY spec_id;
-- +goose Down
DROP TABLE certificates_issuance_leases;
