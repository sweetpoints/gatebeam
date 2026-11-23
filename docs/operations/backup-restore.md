# Encrypted backup and conservative local recovery

Gatebeam collects a new PostgreSQL repeatable-read snapshot on an hourly local
timer, seals a standard tar stream with age to an offline recovery recipient, and
lets the existing worker upload it under `backups/<id>.age` in S3-compatible R2.
The uploaded object is downloaded and SHA-256 checked before `backup_runs` records
success. Export publishes an atomic `current` pointer only after the ciphertext
and manifest receipt are complete. The worker reads that fixed-size pointer and
its bounded files, rather than enumerating historical spool entries. Therefore
43–365 day retention can accumulate more than 2048 directory entries without
blocking new uploads or catalog-driven cleanup. Retention deletes only previously
confirmed runs after another current backup is verified. The latest selected run is always retained. A failed upload,
stale export, missing capsule or inconsistent key epoch produces
`backup_unavailable`; it must not be interpreted as a successful backup.

## Authority and files

| Component | Database and files | Authority |
|---|---|---|
| API/edge/CA/worker role capsule export | Only that role's existing explicit key-file configuration | Seal to public recovery recipient; write only its own capsule subdirectory |
| `backup-export` one-shot service | Dedicated SELECT-only login; public recipient; read-only encrypted capsules; writable ciphertext spool | Consistent database collection; no signing key, API seed, recovery identity, security write or object-store credential |
| Existing worker backup loop | `backup_runs` catalog; ciphertext spool; dedicated backup R2 credential | Upload/read verification and bounded retention; no cross-owner snapshot reads or foreign private-key mounts |
| `backup-restore` local command | Offline recovery identity; a local PostgreSQL 18 recovery-admin connection; existing empty output parent | Create a randomly named new database and directory; invoke owner recovery ports; no network/DNS/Nginx activation |

The CA root private key is never a capsule input and must remain in its separate
offline ceremony custody. The recovery identity must be distinct from every
online age identity; packing the recovery identity into an online capsule is
rejected. Use separate per-role online identities as before. Do not copy them to
the worker or snapshot OS user. The backup code does not provision DB users,
roles, network permissions, systemd units or cloud accounts at runtime.

## Initial setup and scheduled collection

1. Generate and custody a dedicated standard X25519 age recovery identity on an
   offline host. Transfer only its `age1...` public recipient to online config.
   Securely retain the offline identity independently of this backup storage.
2. Apply the embedded schema migrations. As the migration owner, apply the
   embedded `db/roles` goose migrations with `migrate_roles: true` in the selected
   deployment schema, then provision a separate login that receives only
   `gatebeam_backup_snapshot`, and grant that login schema USAGE. Grant the
   existing worker login `gatebeam_backup_worker`. The exporter actively rejects
   owner/superuser, SET-reachable privileged roles, membership administration,
   security-definer execution (including NOINHERIT roles reachable through SET
   ROLE), server file/program and table/column write capabilities. Do not use the migration login for recurring exports.
3. Create `backup-capsules/{api,edge,ca,worker}`. Each subdirectory must be owned
   and writable only by its matching service OS user. Give a separate exporter
   read group directory traversal and file read permission; use setgid mode
   2750 so new encrypted files inherit that read group. The exporter has only
   read access to all four directories. Give the worker only its own capsule
   export directory; it does not need the other three. Use a separate shared
   setgid spool directory for exporter/worker; the worker needs deletion rights
   for confirmed expired ciphertext. Encrypted archive/capsule/metadata files
   are written 0640, including under restrictive process umasks. Live private
   key files remain 0600 and are never placed in the ciphertext spool.
4. Set the following public backup fields in all four role configurations:

   ```json
   {
     "backup_recipient": "age1...",
     "backup_epoch": "operator-key-epoch-1",
     "backup_capsule_directory": "/var/lib/gatebeam/backup-capsules"
   }
   ```

   With backups enabled, every role seals its allowed key files before starting
   its listener/worker. For initial setup, run the role's existing executable
   **as that role's OS user with its existing mounts**, using
   `gatebeam --config /etc/gatebeam/<role>.json --export-backup-capsule`.
   This command exports and exits without starting listeners. API requires its
   identity; CA requires its complete online issuer/root-status/TLS material;
   edge requires management certificate/key/trust and includes configured
   material identity/status profiles; worker includes configured provider and
   notification identities and ACME transport trust. Empty optional worker
   key sets still get an explicit capsule. All paths are selected by composition,
   not by an archive manifest or command supplied by a backup.
5. Configure `deploy/backup/export.example.json` with the public recipient,
   same epoch, ciphertext directories and dedicated SELECT login file. Install
   `gatebeam-backup-export.service` and `.timer` from `deploy/backup/` after
   adapting paths and creating `gatebeam-backup`. The service has a 60-second
   watchdog, 512 MiB memory limit, one CPU quota, 32-task limit and a restricted
   filesystem. The timer runs on boot and hourly, with at most 30 seconds jitter
   and persistent missed-run handling. After reviewing the installed unit,
   enable it with `systemctl enable --now gatebeam-backup-export.timer` and
   inspect `systemctl list-timers gatebeam-backup-export.timer` plus its journal.
6. Add these fields to the existing worker configuration and restart through
   the normal deployment procedure:

   ```json
   {
     "backup_spool_directory": "/var/lib/gatebeam/backup-spool",
     "backup_credentials_file": "/run/gatebeam/backup-r2.json",
     "backup_retention_days": 30,
     "backup_max_age_minutes": 120
   }
   ```

   The R2 file uses the existing S3 transport configuration keys `Endpoint`,
   `Bucket`, `Region`, `AccessKey`, `SecretKey`. Scope the credential to the
   designated backup bucket/prefix with Put/Get/Delete capability; provision
   the bucket separately. Use HTTPS for actual R2. Worker backup upload runs
   immediately and then every minute in an independent loop; health and other
   queues are not used as the backup scheduler.

Changing any capsule file under the same epoch fails explicitly. On rotation,
keep role files immutable while a process is using them, set a new common epoch,
export all four roles under their own credentials, and update the exporter epoch
only after all four `current.json` pointers agree. Restart/reload the owning
roles through their normal operation. The exporter checks capsule content hashes,
recipient and epoch both before and after the database transaction; partial
rotation makes the export fail. Never edit or roll back current pointers by hand.
Old immutable capsules remain available for existing backup copies. Key changes
outside this owner startup/export procedure are unsupported and cannot be made
coherent by a timer reading live foreign key mounts.

The database snapshot carries the actual transaction snapshot, timestamp, schema
migration digest, compiled table contract and SHA-256/size for each payload.
Deployment candidates, logical revisions, material bindings, certificate versions,
encrypted provider state and CA/identity state come from one transaction. Active
Nginx trees, sockets, symlinks, running processes and host/cloud configuration are
not copied or replayed. Logical/material records are inputs to a later fresh,
manual deployment; they are not evidence that the recovered gateway is healthy.
Archived Parquet objects remain in their existing archive storage; database
manifests/reference checksums are preserved, not duplicate copies of the log bucket.

Backup delivery history has a backup-owned compact recovery projection in that
same read-only transaction Scope. It retains every receipt's ID, recorded backup time,
ciphertext digest/length and version/snapshot/epoch/schema/recipient provenance,
but omits redundant historical per-file manifest details. The live catalog keeps
its full manifests. Restored historical `backup_runs.manifest` records explicitly
say `detail_status: omitted_for_recovery` and `artifact_verification: required`;
these are delivery/retention receipts, not verified-restorable archive reports.
The encrypted object and a fresh offline `Verify` remain authoritative. New
manifests record the public recovery recipient; older receipts without that field
retain an empty value with `recipient_recorded: false`, never an inferred one.
This keeps 8760 hourly receipts for 365 days within the unchanged 32 MiB recovery
member bound without discarding useful delivery history or increasing size limits.

Limits are 128 MiB total archive, 32 MiB per data member, 8 MiB per serialized
JSON row, 1 MiB per capsule file, 100,000 rows per table, 45 seconds for collection
and 60 seconds per upload cycle. Export and offline verification share the same
row size/object-shape contract; an oversized row fails before an uploadable
artifact or new current pointer is created.
Restore supports the exact schema digest compiled into the recovery executable;
use the matching release binary. New migrations must explicitly update the backup
contract. Provision a bounded spool filesystem and alert on exporter failures or
lack of a fresh `backup_runs` receipt; outage accumulation is not automatically
removed as unconfirmed backups. The current pointer removes the directory-scan
limit, not the need to size and bound spool storage for the selected retention.
When upgrading a spool created before the current-pointer format, run a fresh
`backup-export` once (or let its next scheduled invocation finish) before the
worker can select a backup; no historical ciphertext or receipts need rewriting.
Maximum retention is 365 days, freshness at most 24 hours, and each cycle retires
at most 100 confirmed runs.

## Local verification and recovery

Download the selected R2 object using operator tooling and compare its SHA-256
with a trusted `backup_runs` receipt. age provides authenticated encryption, not
an exporter signature: protect the catalog/spool and confirm the selected source
through the trusted operator channel. Knowledge of the public recipient alone is
not proof that a newly constructed archive came from this gateway.

Use a separate local PostgreSQL 18 recovery instance when possible. Stop any
recovery-host API/CA/worker/edge services. The recovery connection must use an
explicit loopback IP or local Unix socket, no fallback hosts, and an operator
admin able to create databases and connect despite `CONNECTION LIMIT 0` (normally
local postgres admin). Do not use a production remote DSN. Set `sslmode=disable`
for the owned loopback/Unix recovery connection to avoid an implicit fallback;
this does not disable TLS verification for any gateway/backend connection.

Use `deploy/backup/restore.example.json`, a local source regular file, offline
identity regular file and a new empty parent directory. Then run:

```sh
gatebeam --config /offline/recovery.json
```

The application verifies the whole age stream, manifest, exact schema/table
allowlist and all nested capsules. The subsequent restore reopens, decrypts and
checks the source and opaque in-memory report again. It rejects changed sources,
forged reports, arbitrary activation modes, traversal, tar links and unknown
file labels. Data is standard JSON mapped only to built-in table/column contracts;
no SQL, commands, roles, grants, URLs or file paths from the archive are executed.

Output is a generated `gatebeam_restore_<random>` database and a directory of the
same name, with fixed `api/edge/ca/worker` file names and `recovery.json`. Existing
databases/directories are never overwritten. Database CONNECT is revoked from
PUBLIC and its connection limit stays zero; recovered files remain 0600 inside
0700 directories. A handled failure removes only newly created partial output.
After a killed process or host interruption, an inert partially staged database
may remain; identify it by generated name, inspect it offline and remove/retry it
manually. Do not activate an output lacking a successful recovery receipt.

## Conservative security and manual activation

There is deliberately no “trusted=true”, timestamp override or automatic mode.
Without independently proven latest security authority, every recovery is
`conservative-local`:

- Identity disables old accounts, erases password hashes/TOTP seeds/invitations,
  revokes sessions/tokens, consumes recovery/challenge state and removes grants.
  Old password plus new TOTP cannot take over a restored account.
- A one-shot local identity rebootstrap gate is armed. Configure the existing
  interactive `bootstrap` CLI against this isolated DB with a **new account name**
  and identity file, and use `--show-bootstrap` at the local terminal. Enroll the
  new password/TOTP manually. The gate is consumed transactionally; old account
  IDs stay disabled. Runtime API/worker logins must not be able to arm this gate.
- PKI disables principals, consumes EABs, deactivates ACME accounts, invalidates
  unfinished orders and permanently revokes every known issued certificate.
  A certificate absent from the backup remains unknown, never implicitly good.
  Every restored issuer is permanently quarantined and cannot restart signing
  or reserve new serials. Runtime roles may only read that quarantine.
- Certificates disables restored resources and clears in-flight work leases.
  Deployment clears active runtime/route receipts and marks historical releases
  failed for activation. Notification channels/deliveries are disabled. Platform
  jobs/outbox are cleared so old work does not resume on process startup.

**Unknown is not CRL-revoked.** An old intermediate can validate an unknown
post-backup leaf even when every known leaf is listed in its CRL. Keep the affected
mTLS routes unavailable until the offline root operator issues a standard root
CRL revoking that old intermediate and installs a new intermediate/trust chain,
or replaces the old trust anchor so the old chain is no longer trusted. Keep the
root key offline. Distribute current root and intermediate CRLs to each original
Nginx/standard client verifier and verify complete chain revocation. Never disable
certificate verification, invent a CRL “unknown” status, or erase the quarantine.
The offline root ceremony and distribution may require an outage.

After fresh administrative enrollment, explicit principal/EAB authorization, new
certificates, renewed provider credentials, trust rotation and offline inspection
of recovered configuration, provision the runtime roles in the new DB. Only then
manually change local connection limits/CONNECT grants and service configuration,
rebuild fresh deployment artifacts, perform native configuration/handshake checks,
and publish through the ordinary release procedure. Copying a recovered key or
historical release receipt is not activation authorization. Restorer itself never
opens an ingress listener, reloads Nginx, changes DNS/cloud state or starts roles.

## Reproducible checks and limits of evidence

`./scripts/check-backup.sh` builds a fresh Linux binary, starts resource-limited
owned PostgreSQL 18 and S3-compatible RustFS fixtures, runs real snapshot/age/S3
and isolated restoration tests, and exercises original Nginx CRL-only mTLS.
It requires Docker; missing dependencies fail, not skip. The native exporter
fixture mounts only the SELECT login and encrypted capsules, never any recovery
or other-role private key. Composition tests drive the same worker loop with
explicit timer ticks and collect a second database update into a second object.
The systemd unit is delivered configuration; enabling the host timer, production
R2 access, production process/mount topology and full combined-role/capacity
acceptance require deployment/O6 verification. These checks do not certify the
unrelated first-publication SNI/watchdog, future-NotBefore or full receipt gates.

### Historical key availability during online identity rotation

Each role's current capsule records a bounded immutable history of previous
capsule content hashes. Snapshot collection includes every referenced historical
capsule and fails if one is absent or changed; it never truncates that history to
make a backup succeed. Offline verification checks the encrypted history as well
as the manifest. Historical files restore only under generated
`<role>/history/<capsule-sha256>/<fixed-label>` directories, with the same private
permissions and allowlist as current material. This keeps older DB-referenced
encrypted certificate versions decryptable after an online role identity changes.
Recovered key availability does not reauthorize a certificate, issuer, credential
or release: all owner quarantine rules still apply.

There are at most eight historical capsules per role, in addition to its current
capsule, within the overall archive bounds. Exhaustion fails a further rotation;
resolve old references through an owner-controlled migration/retirement procedure
before planning another epoch. Do not delete historical capsule files to bypass
this check. The public recovery recipient is immutable across this history;
changing it requires a separately reviewed offline re-encryption procedure, not
an online key swap or a second offline identity mounted on the gateway.
