# Acceptance record template

Copy this template into the approved private evidence store, not a per-run
tracked repository document. Leave an unexecuted gate pending or failed; never
replace a mandatory gate with a documentation-only waiver.

## Identity and separate decisions

- Source commit / clean status / platform / tool versions:
- Unit + architecture checks:
- CI run URL and exact tested commit (or not run):
- Local image IDs, binary SHA-256 and build manifest location:
- Published registry digests (or not published):
- Owned local acceptance decision / reviewer:
- Real provider and business acceptance decision:
- Production deployment target / explicitly approved change / time (or not deployed):

## Required owned local gates

Use `GATEBEAM_TEST_OPENSSL=/absolute/openssl scripts/check-system.sh`.
Attach `.work/system-acceptance/results.json` and its complete stage list.
Keep stage logs private; retain body-free failure metadata before cleanup.

| Gate | Actual evidence and exit status | Result |
|---|---|---|
| Architecture + SQL ownership + role negative capabilities | import rules, literal SQL table inventory, real grants/42501, no DDL | |
| Transactions/events | rollback, concurrent idempotency, duplicate/out-of-order events, current authority/lease fences | |
| Separate API/worker/edge HTTP-01 | actual shared webroot; first issuance before first verified publication | |
| Owned DNS-01 | standard ACME, scoped CF stub create/delete ownership, recursive/authoritative propagation | |
| Periodic runtime generation | health failure/recovery, changed DNS, draft preserved, expired old publisher, manual publication/lease race | |
| Native outage | API/DB unavailable existing traffic; worker/DB down CF TTL rejects only expired CF site | |
| Route budget | sites/domains/routes, exact route outcomes, elapsed vs 5s/concurrency8, no truncation | |
| Native receipt consistency | no pending/verifying/restoring task; journal/DB active binding/artifact/version/native TLS/private version agree | |
| Standard PKI + existing-root rotation | CSR/signing, separate root OCSP delegate, monotonic root CRL, old issuer revoked, imported epoch restart | |
| Restore | isolated restore quarantine, old credentials disabled, unknown post-backup CRL-only rejection after approved rotation | |
| Compose | six default runtime services, required image configuration, built UI served, process limits, negative mounts/socket/network, CA restart; separate development database | |
| Browser auth / ingress / PKI / operations | fresh Chrome contexts; current credentials and safe failure metadata | |
| Archive/query/backup | real local S3, source FD pinning/cancellation, export/restore/cipher-only backup worker | |
| Capacity | every tier below, actual resource and I/O measurements | |

Ordinary `go test` excludes explicitly tagged integration/native/browser fixtures.
The full runner executes their dedicated stages; a unit-suite skip is not their
completion. One failing stage keeps the whole result incomplete. Record any
original unresolved failure separately from successful later executions.

## Capacity worksheet

Record rows, object count, exact Parquet bytes, selected manifest bytes, query
span/filter, returned row count, fixed image ID, elapsed time, peak child RSS,
cgroup memory/CPU/PID/oom events, FD release and S3 GET/HEAD/response bytes.
Do not call manifest bytes actual network scan bytes: column pruning may read
only small ranges. Cold means a fresh DuckDB process; repeated hot measurements
may reuse OS/object-store caches. No claim of physical disk cold cache is made
without a measured cache-control procedure.

| Tier | Required workload | Local cold / repeated | S3 cold / repeated | Resource/I/O evidence |
|---|---|---|---|---|
| small | 100,000 rows / 100 objects; wide and narrow spans | | | |
| million | 1,000,000 rows / 1000 objects; wide and narrow spans | | | |
| max objects | 1,000,000 rows / 4096 local objects, cancellation + successful FD release | | n/a: object-count local tier | |
| near limit | 1,000,000 rows / 128 objects, measured bytes near 2 GiB | | | |

Baseline: query memory 512 MiB, CPU1, PID64, tmpfs1GiB, DuckDB320MiB,
spill900MiB, thread1/concurrency1, timeout60s, manifest2GiB/4096objects;
query-only child NOFILE12288. Record changed bounds and evidence/ruling explicitly.
No latency/S3 cost SLA follows from a local fixture.

## Production prerequisites and disposition

Record separately: real public CA issuance/renewal, real Cloudflare token scope
and authoritative ranges/AOP paths, R2 read/write permissions and costs, actual
DNS/TTL convergence, upstream business semantics, origin default certificates
and uniform Host-vhost mTLS/OCSP, host clock synchronization, offline-root
custody, backup schedule ownership, recovery observation and rollback decision.
None is implied by owned stub tests. Do not install timers, change DNS, send
notifications or publish artifacts as a side effect of filling this template.
