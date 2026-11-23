-- name: LockIncident :one
SELECT source_version,state FROM notification_incidents WHERE fingerprint=$1 FOR UPDATE;
-- name: SaveIncident :exec
INSERT INTO notification_incidents(fingerprint,source_version,state,event) VALUES($1,$2,$3,$4)
ON CONFLICT(fingerprint) DO UPDATE SET source_version=excluded.source_version,state=excluded.state,event=excluded.event;
-- name: SaveTransition :exec
INSERT INTO notification_transitions(id,fingerprint,event) VALUES($1,$2,$3);
-- name: QueueTransition :exec
INSERT INTO notification_deliveries(transition_id,channel_id)
SELECT $1,id FROM notification_channels WHERE enabled ON CONFLICT DO NOTHING;
