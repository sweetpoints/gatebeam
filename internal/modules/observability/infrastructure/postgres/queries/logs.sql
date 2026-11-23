-- name: EnsureSegment :exec
INSERT INTO observability_segments(id,fingerprint,source_name,physical_id) VALUES($1,$2,$3,$1) ON CONFLICT DO NOTHING;
-- name: LockSegment :one
SELECT id,fingerprint,source_name,source_offset,dropping,anchor,updated_at,node_id FROM observability_segments WHERE id=$1 FOR UPDATE;
-- name: BatchChecksum :one
SELECT source_checksum FROM observability_batches WHERE id=$1;
-- name: InsertBatch :exec
INSERT INTO observability_batches(id,segment_id,start_offset,end_offset,source_checksum,objects,invalid_count,schema_count,oversize_count,node_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10);
-- name: AdvanceSegment :exec
UPDATE observability_segments SET source_offset=$2,dropping=$3,source_name=$4,anchor=$5,updated_at=clock_timestamp() WHERE id=$1;
-- name: MergeBucket :exec
INSERT INTO observability_stats(minute,site_id,route,method,status_class,requests,micros,bytes,histogram,config_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
ON CONFLICT(site_id,minute,config_id,route,method,status_class) DO UPDATE SET
requests=observability_stats.requests+excluded.requests,micros=observability_stats.micros+excluded.micros,bytes=observability_stats.bytes+excluded.bytes,
histogram=ARRAY[
observability_stats.histogram[1]+excluded.histogram[1],observability_stats.histogram[2]+excluded.histogram[2],
observability_stats.histogram[3]+excluded.histogram[3],observability_stats.histogram[4]+excluded.histogram[4],
observability_stats.histogram[5]+excluded.histogram[5],observability_stats.histogram[6]+excluded.histogram[6],
observability_stats.histogram[7]+excluded.histogram[7],observability_stats.histogram[8]+excluded.histogram[8],
observability_stats.histogram[9]+excluded.histogram[9],observability_stats.histogram[10]+excluded.histogram[10],
observability_stats.histogram[11]+excluded.histogram[11],observability_stats.histogram[12]+excluded.histogram[12]],ingested_at=clock_timestamp();
-- name: QueryBuckets :many
SELECT * FROM observability_stats WHERE site_id=ANY(sqlc.arg(sites)::text[]) AND minute>=sqlc.arg(from_time) AND minute<sqlc.arg(to_time)
AND (sqlc.arg(route)::text='' OR route=sqlc.arg(route)) AND (sqlc.arg(method)::text='' OR method=sqlc.arg(method))
AND (sqlc.arg(status_class)::integer=0 OR status_class=sqlc.arg(status_class)) AND (sqlc.arg(config_id)::text='' OR config_id=sqlc.arg(config_id)) ORDER BY minute,site_id,config_id,route,method,status_class LIMIT 4097;
