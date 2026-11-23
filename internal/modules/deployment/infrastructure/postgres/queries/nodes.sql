-- name: LockNodeRegistry :one
SELECT id FROM deployment_generation WHERE id=true FOR UPDATE;
-- name: CanManageNodes :one
SELECT has_table_privilege(session_user,'deployment_nodes'::regclass,'INSERT') AND has_table_privilege(session_user,'deployment_nodes'::regclass,'UPDATE');
-- name: NodeConnectionPrincipal :one
SELECT session_user::text;
-- name: RegisteredNode :one
SELECT id,epoch,principal::text,state,enabled,legacy_origin,registration FROM deployment_nodes WHERE id=$1;
-- name: RegisterNode :exec
INSERT INTO deployment_nodes(id,epoch,principal,registration,legacy_origin) VALUES($1,$2,$3,$4,$5)
ON CONFLICT(id) DO UPDATE SET epoch=excluded.epoch,principal=excluded.principal,registration=excluded.registration,legacy_origin=deployment_nodes.legacy_origin OR excluded.legacy_origin,state='active',registered_at=clock_timestamp();
-- name: EnabledNodeTargets :many
SELECT id,epoch,state,registration FROM deployment_nodes WHERE enabled ORDER BY id;
-- name: EnableNodeMembership :exec
UPDATE deployment_nodes SET enabled=(id=ANY(sqlc.arg(nodes)::uuid[]));
-- name: SetNodeStatus :execrows
UPDATE deployment_nodes SET state=$3 WHERE id=$1 AND epoch=$2;
-- name: RetireDesired :exec
UPDATE deployment_desired SET is_current=false WHERE is_current;
-- name: InsertDesiredNode :exec
INSERT INTO deployment_desired(release_id,node_id,node_epoch) VALUES($1,$2,$3)
ON CONFLICT(release_id,node_id,node_epoch) DO UPDATE SET is_current=true;
-- name: CurrentDesiredNode :one
SELECT release_id::text FROM deployment_desired WHERE node_id=$1 AND node_epoch=$2 AND is_current;
-- name: NodeReportAllowed :one
SELECT EXISTS(SELECT 1 FROM deployment_desired d WHERE d.release_id=sqlc.arg(release_id)::uuid AND d.node_id=sqlc.arg(node_id)::uuid AND d.node_epoch=sqlc.arg(node_epoch)::bigint AND d.is_current)
OR EXISTS(SELECT 1 FROM deployment_node_runtime r WHERE r.node_id=sqlc.arg(node_id)::uuid AND r.node_epoch=sqlc.arg(node_epoch)::bigint AND r.release_id=sqlc.arg(release_id)::uuid)
OR EXISTS(SELECT 1 FROM deployment_runtime legacy WHERE legacy.id=true AND legacy.release_id=sqlc.arg(release_id)::uuid);
-- name: NodeEvent :one
SELECT body,material_bindings,observed_at FROM deployment_node_events WHERE node_id=$1 AND node_epoch=$2 AND release_id=$3 AND event_id=$4;
-- name: LatestNodeEventTime :one
SELECT max(observed_at)::timestamptz FROM deployment_node_events WHERE node_id=$1 AND node_epoch=$2 AND release_id=$3;
-- name: InsertNodeEvent :exec
INSERT INTO deployment_node_events(node_id,node_epoch,release_id,event_id,body,material_bindings,observed_at) VALUES($1,$2,$3,$4,$5,$6,$7);
-- name: SaveNodeRuntime :exec
INSERT INTO deployment_node_runtime(node_id,node_epoch,release_id,body,material_bindings,observed_at) VALUES($1,$2,$3,$4,$5,$6)
ON CONFLICT(node_id,node_epoch) DO UPDATE SET release_id=excluded.release_id,body=excluded.body,material_bindings=excluded.material_bindings,observed_at=excluded.observed_at;
-- name: CurrentNodeRuntime :one
SELECT release_id::text,body,material_bindings,observed_at FROM deployment_node_runtime WHERE node_id=$1 AND node_epoch=$2;
-- name: NodeReleaseObservations :many
SELECT d.node_id,d.node_epoch,CASE WHEN n.epoch<>d.node_epoch THEN 'stale' WHEN NOT n.enabled THEN 'disabled' ELSE n.state END::text AS node_state,e.body
FROM deployment_desired d JOIN deployment_nodes n ON n.id=d.node_id
LEFT JOIN LATERAL(SELECT body FROM deployment_node_events WHERE node_id=d.node_id AND node_epoch=d.node_epoch AND release_id=d.release_id ORDER BY observed_at DESC,event_id DESC LIMIT 1) e ON true
WHERE d.release_id=$1 ORDER BY d.node_id,d.node_epoch;

-- name: LegacyOriginNode :one
SELECT id::text FROM deployment_nodes WHERE legacy_origin;
