# Local log producer and site statistics

The worker consumes the edge's controlled log volume and writes a separate local
Parquet spool. Run the worker with read access to the edge's UID 101 log files
(same UID in separate containers). The archival worker also receives controlled
log-volume write access for the retirement lifecycle described below. Do not mount the edge release directory or any CA private key.
`log_directory` and `log_spool_directory` are process configuration, never API
parameters. Defaults are `/var/lib/gatebeam/logs` and `/var/lib/gatebeam/spool`.
The example worker configuration lists both explicitly. Provision these volumes
and permissions before starting the process.

The owning log loop runs independently of health/DNS and certificate preparation.
It schedules only the fixed `deployment.rotate_logs` job, at most once a minute.
The edge retains its existing process/UID boundary and executes rename + USR1.
A zero-byte `.closed` marker is fsynced only after the master and workers have
released the renamed descriptors. Unmarked segments remain readable, but an
incomplete tail is retained for a later read. Copytruncate is prohibited. O1 never deletes sources; O2 performs only the
archive-confirmed retirement described below. Source device/inode, initial fingerprint, committed offset and a
trailing fingerprint detect replacement, shortening and changed cursor content;
these checks assume a trusted append-only Nginx volume, not an adversarial writer.

Each operation reads at most 1 MiB and emits at most 1,024 accepted rows, with a
16 KiB line limit. Oversized records are drained across bounded batches with a
persisted discard state and counted once. A partial live record never advances
the cursor. Reader discovery allows at most 2,048 volume entries and 1 GiB of
access-log bytes; the spool allows 16,384 entries and reserves 16 MiB beneath its
1 GiB budget before writing; it also reserves up to 4,097 directory/file entries for a batch. Spool enumeration reads at most 64 entries per page, shares entry/byte budgets across subdirectories, checks cancellation between reads, and rejects directory nesting below the site/date/hour layout. Use a filesystem quota on the separate spool volume
as the physical backstop. These application limits do not cap Nginx's source
writes: archive/retention cleanup uses the O2 lifecycle below, and source volume provisioning
must keep source exhaustion from consuming the rest of the host. At a limit,
collection reports `LogIngestFailed` with a fixed `capacity` reason and retains
unread sources; it never silently deletes unarchived data.

Parquet uses Snappy, schema version 1, and site/UTC-date/hour partitions. Files
are fsynced before publication, parent directories are fsynced before return,
and the same batch/object key cannot overwrite different existing content.
`observability_batches.objects` contains each object's relative key, schema,
row count, byte size, checksum and time range. Only these committed receipts
are eligible inputs for O2. A crash can leave unreferenced spool objects or
`.pending-*` files; they consume the spool budget and are not falsely marked
archived. No object is removed before O2 verifies archive ownership and retention.

The source schema contains only native generated request ID, site ID, compiler
logical configuration hash (SHA-256 of the immutable snapshot version, distinct from native runtime generation), fixed route index (`-1` for the implicit root location,
`default` for a response before location selection), configured `path_pattern`,
target ID, whitelisted method, time, bounded status/bytes/duration, fixed upstream
outcome and native limit statuses. `path_pattern` is a configuration label,
never the actual request path. Request bodies, headers, cookies, query strings,
client addresses and raw upstream strings are not retained. HTTP `error_log`
remains suppressed. The ingestion allowlist also protects against older log
producers containing extra fields. Operators must not put secrets into static
route configuration labels.

Rejected syntax, unsupported schema and oversized lines produce counts and a
body-free `LogRecordsRejected` outbox event in the same transaction as the batch,
statistics and source cursor. No raw quarantine payload is written. Fixed
`LogIngestFailed` outbox events and rate-limited process diagnostics expose
operational failures; a database outage can prevent the durable event itself,
so stderr remains the fallback and never contains raw errors or log records.
O3 owns incident handling and external delivery.

`composition.NewStatistics` supplies the owner `stats.Service.Query` for O5.
It reloads the current credential and current site/group grants under the
identity then ingress watermarks, and reads statistics in that same Scope.
Callers supply 1–100 site IDs, aligned minute endpoints spanning at most 24 hours,
and optional configuration hash/fixed route/method/status-class filters. The configuration hash is part of the bucket route identity, so reused route indices from different published configurations stay separate. More than 4,096 returned
buckets fails with capacity rather than returning a misleading partial range.
Counts, duration sum and a mergeable 12-bucket histogram are persisted separately;
P50/P95 are bucket upper-bound approximations of the merged population. The
response includes the latest ingestion timestamp. There is no Prometheus or exporter. O5 owns the management HTTP adapter and UI.

Apply embedded goose role migrations with the explicit migration configuration
(`migrate_roles: true`), then grant the reader/worker memberships
to the existing process logins. Identity/ingress authorization read permissions
and the existing fixed job enqueue permission are separate owner grants; the
observability roles confer no signing, CA or certificate secret capability.

## Archive and historical query operation

O2 extends this owner with `composition.NewHistory` (`Submit`/`Fetch`) for O5.
API receives only current authorization and metadata adapters. It has no DuckDB,
query socket or R2 credentials. The ordinary worker independently polls durable
query jobs and archives committed batches. The query-worker has no database
credential or write permission; only the worker and query-worker mount the
private UID-101 `/run/query/query.sock`. Requests are bounded standard HTTP/JSON
with a typed filter and frozen object list, never SQL or process arguments.

Compose's `edge` profile includes the production query-worker assembly. Build
a fresh static binary with `scripts/build-edge.sh` before image builds. Provision
the spool and socket volumes for UID 101. The edge log volume is shared writable
with worker specifically for archive-confirmed retirement; edge releases and
private keys are not mounted in query-worker. Query uses its own read-only R2
credential file, while worker receives a separate bucket-scoped archival
read/write/delete credential file. Copy the example configuration structure
without checking actual credentials into Git. Keep the R2 bucket private.

An archive operation uploads to `pending/`, reads back SHA-256, copies to its
immutable `logs/` key, reads back SHA-256 again, and removes the staging object.
Only then does its transaction publish the manifest and `ArchiveCommitted`
outbox event. Retry verifies an existing final object and never overwrites a
mismatching digest. Local Parquet removal follows the committed manifest;
restarting between these steps is idempotent. Deletion uses the owner's
`archive.Service.Delete`: it locks the manifest, refuses while a live queued or
running snapshot references it, excludes it from new queries before remote
deletes, then marks it deleted. Retry of a deleting manifest is safe. Configure
retention through this lifecycle; do not attach an independent R2 lifecycle rule
that removes live manifest objects.

Closed sources require the supervisor `.closed` proof, fully read offset and
all batches archived. The owner writes a durable retirement intent before
unlink, checks the exact closed inode/fingerprint/size, fsyncs the directory,
then retires its logical identity. Crash recovery completes the intent; inode
reuse gets a fresh incarnation and cannot resume the retired cursor. Active,
unread or unarchived sources are retained. No copytruncate is supported.
Spool reconciliation takes the same process-shared lock as persist plus cursor
commit, scans a bounded number of entries and removes only unreferenced local
Parquet/pending files. Crash orphans count against capacity until reconciled.

Default limits: one executor, 64 queued/cached jobs, 10-minute cache, 60-second
execution, 2 GiB of known manifest bytes, 4,096 objects and 10,000 output rows.
Filters require 1–100 current authorized sites and a time range of at most
31 days; optional fixed route index, method, configuration hash and exact HTTP
status are allowlisted. Over-limit queries fail; results never claim truncated
history. Pages have 100 rows. Fetch rechecks the same current credential and
current site membership on every page, including cached results. Object lists
and cloud URLs are not returned by the API application.

The query container is limited to 512 MiB, one CPU, 64 PIDs and a 1 GiB tmpfs;
DuckDB uses 320 MiB memory, one thread and a 900 MiB spill limit. Credentials go
only through a private stdin pipe; SQL, raw CLI errors and credentials never
enter argv, result rows, audit or diagnostics. Cancellation kills the complete
CLI process group, reaps it, removes its private temporary directory and frees
the single execution slot. Fixed errors expose failure without stderr contents.

`sh scripts/check-logs.sh query` creates bounded owned RustFS and PostgreSQL 18
fixtures and uses real pinned DuckDB v2.0.0/httpfs and Snappy Parquet. The
installer checks CLI release SHA-256 and extension SHA-256, then lets DuckDB
verify the extension's upstream signature and matching ABI. Extension download
occurs only at build/test setup. The signed core extension comes from DuckDB's
[documented official backup repository](https://duckdb.org/docs/preview/extensions/installing_extensions#backup-repositories).
The runtime disables extension auto-install/load and community extensions.
R2 endpoint/region configuration follows the [Cloudflare AWS SDK v2 example](https://developers.cloudflare.com/r2/examples/aws/aws-sdk-go/).
Actual R2 tenant credentials, production volume pressure and cloud-network
throughput remain separate explicitly authorized operational acceptance.


Capacity acceptance requires successful child `getrusage` plus numeric cgroup v2 memory peak/limit, memory event OOM and OOM-kill counters, anonymous/file memory, PID peak/limit and CPU usage metrics. Missing, unreadable or malformed required metrics fail the gate. These are all required measurements; none is silently treated as zero or omitted. `check-capacity.sh` runs the permanent per-metric negative controls before the real populated measurements.
