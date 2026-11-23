-- name: SaveRouteVerification :exec
INSERT INTO deployment_route_verifications(artifact_id,version,generation,checked_at,body) VALUES($1,$2,$3,$4,$5);
-- name: CurrentRouteVerification :one
SELECT evidence.body FROM deployment_route_verifications evidence
JOIN deployment_runtime active ON active.artifact_id=evidence.artifact_id AND active.version=evidence.version || '/' || evidence.generation
ORDER BY evidence.checked_at DESC LIMIT 1;
