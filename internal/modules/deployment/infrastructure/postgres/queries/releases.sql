-- name: SaveCandidate :exec
INSERT INTO deployment_candidates(id,body,input_digest) VALUES($1,$2,$3);
-- name: Candidate :one
SELECT c.body,coalesce(r.state,'prepared')::text AS state,coalesce(r.observed_version,'')::text AS observed_version,coalesce(r.restored_version,'')::text AS restored_version,EXISTS(SELECT 1 FROM deployment_runtime active WHERE active.release_id=c.id) AS effective FROM deployment_candidates c LEFT JOIN deployment_releases r ON r.id=c.id WHERE c.id=$1;
-- name: LockCandidate :one
SELECT id FROM deployment_candidates WHERE id=$1 FOR UPDATE;
-- name: QueueRelease :execrows
INSERT INTO deployment_releases(id) VALUES($1) ON CONFLICT DO NOTHING;
-- name: ListCandidates :many
SELECT c.body,coalesce(r.state,'prepared')::text AS state,coalesce(r.observed_version,'')::text AS observed_version,coalesce(r.restored_version,'')::text AS restored_version,EXISTS(SELECT 1 FROM deployment_runtime active WHERE active.release_id=c.id) AS effective FROM deployment_candidates c LEFT JOIN deployment_releases r ON r.id=c.id ORDER BY c.created_at DESC,c.id LIMIT $1 OFFSET $2;

-- name: RecordOutcome :execrows
UPDATE deployment_releases SET state=sqlc.arg(state),observed_version=sqlc.arg(observed_version),restored_version=sqlc.arg(restored_version) WHERE id=sqlc.arg(id);
-- name: RecordVerified :exec
INSERT INTO deployment_runtime(id,release_id,artifact_id,version) VALUES(true,$1,$2,$3) ON CONFLICT(id) DO UPDATE SET release_id=excluded.release_id,artifact_id=excluded.artifact_id,version=excluded.version,verified_at=clock_timestamp(),material_bindings='[]'::jsonb;
-- name: CurrentVerified :one
SELECT release_id::text,artifact_id,version FROM deployment_runtime WHERE id=true;

-- name: SaveMaterialBindings :exec
UPDATE deployment_runtime SET material_bindings=$1 WHERE id=true;
-- name: CurrentMaterialBindings :one
SELECT artifact_id,version,verified_at,material_bindings FROM deployment_runtime WHERE id=true;
