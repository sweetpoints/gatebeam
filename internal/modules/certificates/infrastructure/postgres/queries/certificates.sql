-- name: CertificateReadLock :exec
SELECT generation FROM certificates_watermark WHERE singleton FOR SHARE;
-- name: CertificateWriteLock :exec
SELECT generation FROM certificates_watermark WHERE singleton FOR UPDATE;
-- name: CertificateResource :one
SELECT r.kind,r.id::text,v.revision,r.enabled,v.body,v.pem,v.secret FROM certificates_resources r JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id AND v.revision=CASE WHEN $3::bigint=0 THEN r.revision ELSE $3::bigint END WHERE r.kind=$1 AND r.id=$2::uuid;
-- name: CertificateSpecs :many
SELECT r.kind,r.id::text,v.revision,r.enabled,v.body,v.pem,v.secret FROM certificates_resources r JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id WHERE r.kind='spec' ORDER BY r.id,v.revision;
-- name: CertificateCreate :exec
INSERT INTO certificates_resources(kind,id,revision,enabled) VALUES($1,$2,1,$3);
-- name: CertificateUpdate :execrows
UPDATE certificates_resources SET revision=revision+1,enabled=$4 WHERE kind=$1 AND id=$2 AND revision=$3;
-- name: CertificateRevision :exec
INSERT INTO certificates_revisions(kind,id,revision,body,pem,secret) VALUES($1,$2,$3,$4,$5,$6);
-- name: CertificateCurrent :one
SELECT v.body,v.certificate_pem,v.encrypted_key FROM certificates_attempts a JOIN certificates_versions v ON v.id=a.current_version WHERE a.spec_id=$1 AND a.spec_revision=$2;
-- name: CertificateAttemptCreate :exec
INSERT INTO certificates_attempts(spec_id,spec_revision) VALUES($1,$2) ON CONFLICT DO NOTHING;
-- name: CertificateClaim :one
UPDATE certificates_attempts SET token=$3,lease_until=$4 WHERE spec_id=$1 AND spec_revision=$2 AND lease_until<clock_timestamp() AND next_attempt<=clock_timestamp() RETURNING failures,next_attempt;
-- name: CertificateVersion :exec
INSERT INTO certificates_versions(id,spec_id,spec_revision,body,certificate_pem,encrypted_key) VALUES($1,$2,$3,$4,$5,$6);
-- name: CertificateCommit :execrows
UPDATE certificates_attempts SET current_version=$4,token='',lease_until='-infinity',failures=0,next_attempt='-infinity' WHERE spec_id=$1 AND spec_revision=$2 AND token=$3 AND lease_until>clock_timestamp();
-- name: CertificateFailure :execrows
UPDATE certificates_attempts SET token='',lease_until='-infinity',failures=$4,next_attempt=$5 WHERE spec_id=$1 AND spec_revision=$2 AND token=$3;
-- name: CertificateResources :many
SELECT r.kind,r.id::text,r.revision,r.enabled,v.body,v.pem,v.secret FROM certificates_resources r JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id AND v.revision=r.revision WHERE r.kind=$1 ORDER BY r.id LIMIT 1000;
-- name: CertificateEnable :execrows
UPDATE certificates_resources SET enabled=$4 WHERE kind=$1 AND id=$2 AND revision=$3;
-- name: CertificateStatus :one
SELECT body FROM certificates_status WHERE trust_id=$1 AND trust_revision=$2 AND profile_digest=$3 ORDER BY created_at DESC LIMIT 1;
-- name: CertificateStatusSave :exec
INSERT INTO certificates_status(trust_id,trust_revision,generation,profile_digest,body) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING;

-- name: CertificatePreparationDue :many
SELECT r.kind,r.id::text,r.revision,r.enabled,v.body
FROM certificates_resources r
JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id AND v.revision=r.revision
LEFT JOIN certificates_preparations p ON p.kind=r.kind AND p.id=r.id AND p.revision=r.revision
LEFT JOIN certificates_issuance_leases lease ON r.kind='spec' AND lease.spec_id=r.id
LEFT JOIN certificates_attempts a ON r.kind='spec' AND a.spec_id=r.id AND a.spec_revision=r.revision
WHERE (lease.spec_id IS NULL OR lease.lease_until<clock_timestamp()) AND r.enabled AND (r.kind='trust' OR (r.kind='spec' AND v.body->>'method'='acme' AND a.current_version IS NULL))
AND (p.kind IS NULL OR (p.lease_until<clock_timestamp() AND p.next_attempt<=clock_timestamp()))
AND (r.kind='trust' OR a.spec_id IS NULL OR (a.lease_until<clock_timestamp() AND a.next_attempt<=clock_timestamp()))
ORDER BY COALESCE(p.next_attempt,'-infinity'::timestamptz),r.kind,r.id LIMIT 20;
-- name: CertificatePreparationCreate :exec
INSERT INTO certificates_preparations(kind,id,revision) VALUES($1,$2,$3) ON CONFLICT DO NOTHING;
-- name: CertificatePreparationClaim :one
UPDATE certificates_preparations SET token=$4,lease_until=$5 WHERE kind=$1 AND id=$2 AND revision=$3 AND lease_until<clock_timestamp() AND next_attempt<=clock_timestamp() RETURNING failures;
-- name: CertificatePreparationFinish :execrows
UPDATE certificates_preparations SET token='',lease_until='-infinity',failures=$5,next_attempt=$6 WHERE kind=$1 AND id=$2 AND revision=$3 AND token=$4;
-- name: CertificateLeaseCreate :exec
INSERT INTO certificates_issuance_leases(spec_id) VALUES($1) ON CONFLICT DO NOTHING;
-- name: CertificateLeaseClaim :execrows
UPDATE certificates_issuance_leases SET revision=$2,token=$3,lease_until=$4 WHERE spec_id=$1 AND lease_until<clock_timestamp();
-- name: CertificateLeaseRelease :execrows
UPDATE certificates_issuance_leases SET token='',lease_until='-infinity' WHERE spec_id=$1 AND revision=$2 AND token=$3 AND (NOT sqlc.arg(require_valid)::boolean OR lease_until>clock_timestamp());
-- name: CertificateResourceMetadata :one
SELECT r.kind,r.id::text,v.revision,r.enabled,v.body,v.pem FROM certificates_resources r JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id AND v.revision=CASE WHEN $3::bigint=0 THEN r.revision ELSE $3::bigint END WHERE r.kind=$1 AND r.id=$2::uuid;
-- name: CertificateCurrentMetadata :one
SELECT v.body,v.certificate_pem FROM certificates_attempts a JOIN certificates_versions v ON v.id=a.current_version WHERE a.spec_id=$1 AND a.spec_revision=$2;

-- name: CertificateListMetadata :many
SELECT r.kind,r.id::text,r.revision,r.enabled,v.body FROM certificates_resources r JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id AND v.revision=r.revision WHERE r.kind=$1 ORDER BY r.id LIMIT 1000;
-- name: CertificateSpecsMetadata :many
SELECT r.kind,r.id::text,v.revision,r.enabled,v.body FROM certificates_resources r JOIN certificates_revisions v ON v.kind=r.kind AND v.id=r.id WHERE r.kind='spec' ORDER BY r.id,v.revision;
-- name: CertificateVersionsMetadata :many
SELECT body FROM certificates_versions WHERE spec_id=$1 ORDER BY spec_revision DESC,created_at DESC LIMIT 100;
-- name: CertificateAttemptMetadata :one
SELECT COALESCE(current_version::text,'')::text AS current_version,failures,next_attempt,lease_until FROM certificates_attempts WHERE spec_id=$1 AND spec_revision=$2;
-- name: CertificatePreparationMetadata :one
SELECT failures,next_attempt,lease_until FROM certificates_preparations WHERE kind=$1 AND id=$2 AND revision=$3;
