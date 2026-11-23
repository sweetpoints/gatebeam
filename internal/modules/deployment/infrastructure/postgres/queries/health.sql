-- name: RuntimeFence :one
SELECT generation,dirty,queued_at FROM deployment_generation WHERE id=true FOR UPDATE;
-- name: RuntimeReadFence :one
SELECT generation FROM deployment_generation WHERE id=true FOR SHARE;
-- name: TargetRuntime :one
SELECT body,sequence,checked_at FROM deployment_target_runtime WHERE binding=$1;
-- name: SaveTargetRuntime :exec
INSERT INTO deployment_target_runtime(binding,body,sequence,checked_at) VALUES($1,$2,$3,$4) ON CONFLICT(binding) DO UPDATE SET body=excluded.body,sequence=excluded.sequence,checked_at=excluded.checked_at;
-- name: RuntimeDirty :one
UPDATE deployment_generation SET generation=generation+1,dirty=true WHERE id=true RETURNING generation;
-- name: RuntimeQueued :exec
UPDATE deployment_generation SET dirty=false,queued_at=clock_timestamp() WHERE id=true;
-- name: CloudflareRanges :one
SELECT body FROM deployment_cloudflare WHERE singleton;
-- name: SaveCloudflareRanges :exec
INSERT INTO deployment_cloudflare(singleton,generation,body) VALUES(true,$1,$2) ON CONFLICT(singleton) DO UPDATE SET generation=EXCLUDED.generation,body=EXCLUDED.body;
