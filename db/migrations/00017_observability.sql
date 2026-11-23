-- +goose Up
-- observability owns source watermarks, immutable local object receipts and stats.
CREATE TABLE observability_segments (
 id text PRIMARY KEY, fingerprint text NOT NULL, source_name text NOT NULL,
 source_offset bigint NOT NULL DEFAULT 0 CHECK(source_offset>=0),
 dropping boolean NOT NULL DEFAULT false, anchor text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE observability_batches (
 id text PRIMARY KEY, segment_id text NOT NULL REFERENCES observability_segments(id),
 start_offset bigint NOT NULL CHECK(start_offset>=0), end_offset bigint NOT NULL CHECK(end_offset>start_offset),
 source_checksum text NOT NULL, objects jsonb NOT NULL,
 invalid_count bigint NOT NULL, schema_count bigint NOT NULL, oversize_count bigint NOT NULL,
 committed_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(segment_id,start_offset), UNIQUE(segment_id,end_offset)
);
CREATE TABLE observability_stats (
 minute timestamptz NOT NULL, site_id text NOT NULL, route text NOT NULL, config_id text NOT NULL DEFAULT '', method text NOT NULL,
 status_class integer NOT NULL CHECK(status_class BETWEEN 1 AND 5),
 requests bigint NOT NULL CHECK(requests>=0), micros bigint NOT NULL CHECK(micros>=0), bytes bigint NOT NULL CHECK(bytes>=0),
 histogram bigint[] NOT NULL CHECK(cardinality(histogram)=12),
 ingested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(site_id,minute,config_id,route,method,status_class)
);
CREATE INDEX observability_stats_minute ON observability_stats(minute);
-- +goose Down
DROP TABLE observability_stats,observability_batches,observability_segments;
