# Single-host deployment

The default deployment is one host and one Compose project. All six services
(`nginx`, `management`, `background-jobs`, `internal-ca`, `log-query`, `postgres`)
run on that host; no multi-node deployment is required. It requires
operator-owned host/network/DNS addresses, a PostgreSQL 18 schema, a valid
management certificate and separate service secrets. Local acceptance uses
owned temporary replacements; it does not authorize a real deployment.

## Reproducible artifacts

1. Check out an approved exact commit in an isolated checkout. Record HEAD and
   whether it is clean. Use Go 1.27 and Docker engine architecture `GOARCH`
   (`arm64` by default; explicitly select `amd64` for an amd64 engine).
2. Run `scripts/build-system.sh`. It builds the static binary and web bundle
   from source and the frozen pnpm lockfile. API copies the bundle from the
   web image stage. Host `web/dist`, secrets and node_modules are excluded.
3. Retain `.work/artifacts/manifest.json`, build metadata and build logs in the
   release evidence store. The manifest contains binary SHA-256, exact local
   image IDs, platform, source commit and dirty status. A dirty build is an
   engineering fixture, not an approved release artifact.
4. For distribution, export these exact images or explicitly publish them to
   the approved registry and record resulting manifest digests. Create a
   deployment override selecting those digests (or exact local image IDs for
   an offline host). Deploy with `--no-build`; never rebuild a release on the
   target and call it the same artifact. This repository does not auto-publish.

Compose only references prebuilt images; it contains no `build` declarations.
Builds belong in CI or the separate `scripts/build-system.sh` preparation step,
before deployment. Load or pull the approved images on the target first.

## One runtime configuration entry point

Copy `.env.example` to the ignored `.env` and select the five runtime images:
`GATEBEAM_NGINX_IMAGE`, `GATEBEAM_MANAGEMENT_IMAGE`, `GATEBEAM_JOBS_IMAGE`,
`GATEBEAM_CA_IMAGE` and `GATEBEAM_LOG_QUERY_IMAGE`. Missing references fail before
Compose changes any containers. The example's local tags are only for separately
built local artifacts; production must use approved digests or exact loaded IDs.
An existing release override can still select those image references; provide
`.env` as well because Compose resolves the base file before merging overrides.

`EDGE_BIND`, `EDGE_HTTP_PORT` and `EDGE_HTTPS_PORT` control the host entry points.
Existing loopback 8080/8443 defaults are preserved. A dedicated public gateway
explicitly selects its intended bind address and host ports 80/443 in `.env`.
Process secrets/configuration remain under their separate `secrets/` directories.

The service is named `postgres`; its existing `edge-postgres` data-volume key is
retained to avoid silently selecting an empty database. Service identifiers are
not database/storage identities. Existing Compose projects require a controlled
service-name transition; do not run old and new database services on the same
volume. This rename is not an interruption-free update procedure. There is only
one PostgreSQL service in the runtime file. For a
disposable local development database, use `docker compose -f compose.dev.yaml
up -d`; it uses a separate `gatebeam-development` project. Never combine that
file with the production file. No preview/Node service
is deployed: the API image contains and serves the built web bundle.

All base images, including PostgreSQL, Node, Nginx, Debian and BuildKit, are
pinned in source. BuildKit is an owned container bounded to 1536 MiB, one CPU
and 256 PIDs; each image build has a 240-second deadline. These build resources
are separate from runtime limits. Node is used only in the API image's build
stage, not as a runtime service or separately exported preview image.

## Database and credentials

Use a dedicated migration owner to run `mode: migrate` with a protected
`database_file`. Set the intended schema in the DSN `search_path`. Check the
actual embedded migration version; do not renumber migrations to match a
runbook. Runtime identities must not own schemas/tables or migrate.

Use that protected migration configuration with `"migrate_roles": true` to
apply the embedded `db/roles` goose migrations after schema migration. Role
history is tracked separately in `gatebeam_role_version`; schema and capability
migrators have separate session locks. Re-running is safe for compatible roles.
Existing LOGIN/privileged/owning roles or unexpected inherited/admin authority
are rejected; the migrator does not drop or recreate them. Runtime services
never execute this step. Provision separate LOGIN identities and grant exactly one `gatebeam_runtime_api`,
`gatebeam_runtime_worker`, `gatebeam_runtime_edge` or `gatebeam_runtime_ca`
role plus schema USAGE. Use a secure interactive credential provisioning tool;
do not place passwords in argv, shell history or committed SQL. Remove PUBLIC
schema CREATE where applicable. Store each login's DSN only in its process
secret directory. Test negative writes/DDL with the resulting real login.

The shared jobs/job_attempts grants are table-level queue permissions.
`ClaimKinds` selects process capabilities; it is not database-enforced isolation
between task kinds. Final current-credential, lease, artifact and binding checks
remain mandatory even for fabricated/shared queue rows. CA has only PKI owner
rights; API cannot read certificate DER or reserve signing serials; query has
no database identity or database-network attachment. The offline snapshot
exporter receives its separate read-only role, not a runtime role.

## First installation: files, mounts and startup

This section is for a new installation, not an online update procedure.

Create ignored `secrets/api`, `secrets/edge`, `secrets/worker`, `secrets/ca` and
`secrets/query` directories with mode 0700, files 0600, owned/readable by
container UID 101. Provision `secrets/postgres-password` for PostgreSQL. Copy
and adapt `deploy/edge/*.example.json`, `deploy/query/query.example.json` and
`deploy/pki/ca.example.json` to their configured `/run/gatebeam/*.json` paths.
Replace all reserved names, public recipients, addresses and secret references.
For the internal ACME directory, provision its public transport trust in the
worker and align API/CA exact name allowlists and canonical origin.
Do not mount one parent secrets directory into several services.

| Process | Private capabilities | Shared storage |
|---|---|---|
| management | authentication identity, own DB login | no query socket or signing key |
| nginx | leaf decryption identity, management TLS key, own DB login | runtime journal, logs; HTTP-01 read-only |
| background-jobs | provider/notification identities, scoped archive credentials, own DB login | HTTP-01 write, logs, spool, query socket |
| internal-ca | encrypted intermediate and root OCSP delegate plus dedicated identity, own DB login | no offline root key |
| log-query | read-only object-store credentials | read-only spool, query socket; no DB |

Generate distinct standard age identities for provider and leaf storage, e.g.
`age-keygen -o <private-file>`, and copy only their public recipients into
opposite process/API configurations. Run the existing interactive bootstrap
for the API administrator/identity. See certificate and notification runbooks
for scoped provider credentials and the one-time MFA-protected enrollment flow.
The root and private offline CA ledger never enter these directories or images.

The management certificate must be valid before login. API has its public
certificate/trust; edge alone has its key. Start PostgreSQL, complete migrations
and roles, then edge and verify `/_gatebeam/ready` through the configured trusted
management hostname. Start API, worker, CA and query-worker. The API performs
its own strict management TLS readiness check. No startup flag bypasses it.

For an approved deployment override, the startup sequence is:

```sh
cp .env.example .env
# Select the approved image references and host entry points in .env first.
docker compose up -d --no-build postgres
# Run the explicit migration/role/secret ceremonies before continuing.
docker compose up -d --no-build nginx
docker compose up -d --no-build management background-jobs internal-ca log-query
```

Once initialization is complete, `docker compose up -d --no-build` selects all
six runtime services without profiles. Database-dependent processes wait for
PostgreSQL health; this is readiness sequencing, not automatic schema migration.

The default host binds are loopback 8080/8443. Route the owned public HTTP port
80 and HTTPS port 443 deliberately to these listeners when enabling public
issuance. First HTTP-01 issuance is served by the bootstrap edge from the
worker-write/edge-read shared webroot before first verified site publication.
DNS-01 uses the configured scoped provider, actual DNS propagation and a
standard ACME directory. A local owned stub result is not real-provider success.

Adapt the two protected /29 networks consistently across Compose, API, edge,
worker and target policy. API/database/control addresses must never become
business target destinations. CA ACME/status listeners are private and distinct;
allow only explicitly intended standard clients and challenge networks. Query
has its own egress network; API has neither its socket nor local file paths.
No container mounts a Docker socket. All application processes are UID101,
read-only root, cap_drop ALL and no-new-privileges.

## Capacity and health

Query runtime remains 512 MiB / one CPU / 64 PIDs / 1 GiB tmpfs, DuckDB 320 MiB
memory / 900 MiB spill / one thread / one concurrent query / 60-second timeout.
A frozen manifest is capped at 2 GiB and 4096 objects. Query-worker alone has
soft=hard NOFILE 12288: 4096 verified inherited FDs, 4096 DuckDB reopenings and
4096 reserve. This is an engineering allocation, not a measured optimum. Startup
checks the effective child-exec limit (Go may raise only its own soft limit)
and fails explicitly below 12288. Do not lower the object cap silently or change
host-wide limits. Local data uses verified inherited files, not a 2 GiB tmpfs copy.

Inspect API readiness, CA status/delegate/root-CRL expiry, worker bounded stage
errors, ingestion lag, durable spool/archive receipts, backup freshness and edge
execution reports. An API/DB outage does not stop existing Nginx traffic, but
control actions cannot be confirmed. Native per-site Cloudflare TTL gates reject
new requests after trusted ranges expire even while DB/worker are unavailable;
unaffected sites continue. A process being running is not a healthy CA/status
or verified business route.

Run `GATEBEAM_TEST_OPENSSL=/absolute/openssl scripts/check-system.sh` before
release review. Its ignored stage receipts distinguish full completion from a
partial failure. Native PKI renewal (~74 seconds in the owned fixture) has its
own PostgreSQL stage: stacking it after the rest of integration work in one
120-second watchdog is not a justified suite budget. Per-package Go timeout
remains 90 seconds. No automatic retry turns a failure into acceptance.

## Stop, restore and release rollback

Separating runtime/development configuration does not implement interruption-free
updates. Do not replay the one-time role creation scripts during an update or use
the first-install sequence as an upgrade guarantee. Compatible goose migrations,
versioned privilege changes, metadata backfill and entry-process handoff still
need a dedicated upgrade procedure and old/new-version acceptance. Replacing an
edge container is not equivalent to a Nginx configuration reload.

Record actual native version/TLS, DB active release/artifact/material bindings,
current journal state and whether any apply/generation task is active. A
successful derived update may legitimately end journal `restored`, because it
rebuilds the last verified logical configuration with current security state.
It is accepted only when those exact observations agree and no receipt is pending.
An unknown SNI or clock failure requires body-free stage/clock/receipt evidence
before fixture cleanup; a later pass alone does not establish its cause.

Do not infer runtime activation from disk config or `nginx -T`. Require reload
verification and old-worker listener exit. Stop gracefully within configured
budgets. Restore via the [isolated recovery procedure](backup-restore.md), keep
old issuers quarantined when watermark completeness is unproved, and rotate
with the existing offline root as described in [PKI ceremony](pki-bootstrap.md).
A release rollback still revalidates latest security material; it cannot revive
revoked/expired keys or old authentication credentials. Reinstalling an old
image is not permission to downgrade a database schema.
