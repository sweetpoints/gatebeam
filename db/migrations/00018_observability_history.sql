-- +goose Up
-- Owned exclusively by observability; query executor has no database role.
ALTER TABLE observability_batches ADD COLUMN local_cleaned boolean NOT NULL DEFAULT false;
CREATE TABLE observability_manifests (
 sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 batch_id text NOT NULL UNIQUE REFERENCES observability_batches(id),
 state text NOT NULL DEFAULT 'committed' CHECK(state IN ('committed','deleting','deleted')),
 committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE observability_archive_objects (
 object_key text PRIMARY KEY, manifest_sequence bigint NOT NULL REFERENCES observability_manifests(sequence),
 site_id text NOT NULL, min_time timestamptz NOT NULL, max_time timestamptz NOT NULL,
 bytes bigint NOT NULL CHECK(bytes>0), metadata jsonb NOT NULL
);
CREATE INDEX observability_archive_scope ON observability_archive_objects(site_id,min_time,max_time);
CREATE TABLE observability_queries (
 id uuid PRIMARY KEY, state text NOT NULL CHECK(state IN ('queued','running','succeeded','failed')),
 actor jsonb NOT NULL, filter jsonb NOT NULL, objects jsonb NOT NULL, watermark bigint NOT NULL,
 scan_bytes bigint NOT NULL, result jsonb, error text NOT NULL DEFAULT '',
 lease uuid, lease_until timestamptz, created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 expires_at timestamptz NOT NULL DEFAULT clock_timestamp()+interval '10 minutes'
);
ALTER TABLE observability_segments ADD COLUMN physical_id text;
UPDATE observability_segments SET physical_id=id;
ALTER TABLE observability_segments ALTER COLUMN physical_id SET NOT NULL;
ALTER TABLE observability_segments ADD COLUMN retired boolean NOT NULL DEFAULT false;
ALTER TABLE observability_segments ADD COLUMN retirement_size bigint;
CREATE UNIQUE INDEX observability_active_source ON observability_segments(physical_id) WHERE NOT retired;
-- +goose Down
DROP INDEX observability_active_source;
ALTER TABLE observability_segments DROP COLUMN retirement_size,DROP COLUMN retired,DROP COLUMN physical_id;
DROP TABLE observability_queries,observability_archive_objects,observability_manifests;
ALTER TABLE observability_batches DROP COLUMN local_cleaned;
