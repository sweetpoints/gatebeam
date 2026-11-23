-- name: AppendEvent :exec
INSERT INTO audit(id,action,actor_id,payload) VALUES($1,$2,$3,$4);
-- name: Publish :exec
INSERT INTO outbox(event_id,event_type,schema_version,aggregate_id,aggregate_version,payload) VALUES($1,$2,$3,$4,$5,$6);
-- name: RecentMetadata :many
SELECT id,actor_id,action,occurred_at FROM audit ORDER BY occurred_at DESC,id LIMIT $1 OFFSET $2;
