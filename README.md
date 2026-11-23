# Gatebeam

The default deployment runs on one machine, using one Compose project.

Gatebeam is a single-host ingress gateway with an independent Nginx data plane,
a Go modular control plane, PostgreSQL, and a Vue management UI. Business
servers use standard TLS/mTLS, ACME v2/EAB, OCSP and CRLs; no business agent or
custom client handshake is required. The offline root stays offline.

Start with the [deployment runbook](docs/operations/deploy.md),
[gradual migration procedure](docs/operations/gradual-migration.md),
[private CA ceremony](docs/operations/pki-bootstrap.md), and
[backup/recovery procedure](docs/operations/backup-restore.md).

GitHub Actions runs the complete acceptance suite on native Linux amd64 and
arm64 for pull requests and pushes to `main`. Both jobs build and test their
images locally.

Deployment files have separate purposes:

| File | Purpose |
|---|---|
| `compose.yaml` | Six default runtime services; prebuilt images only, no profiles |
| `.env.example` → `.env` | Image references and host HTTP/HTTPS bindings |
| `compose.dev.yaml` | Standalone disposable development database |

Runtime service names describe duties on that one host:

| Service | Responsibility |
|---|---|
| `nginx` | Public HTTP/HTTPS entry and local configuration supervisor |
| `management` | Management web console and API |
| `background-jobs` | Renewal, probes, archival, notifications and backups |
| `internal-ca` | Standard internal ACME/OCSP/CRL authority |
| `log-query` | Resource-limited local/R2 historical log queries |
| `postgres` | The single local PostgreSQL database |

For a new installation, follow the runbook's database/secret initialization;
after initialization, use `docker compose up -d --no-build`. This is not an
interruption-free upgrade command. Persistent-volume identities are preserved. Existing deployments need a
controlled service-name transition; service renaming is not an online upgrade.

Run `scripts/check-system.sh` with `GATEBEAM_TEST_OPENSSL` pointing to OpenSSL 3
for the complete owned local acceptance matrix. It requires Go 1.27, Python 3,
Docker/buildx, Node/pnpm and a fresh Chrome installation. All four browser
suites and all capacity tiers are mandatory. `scripts/check-system.sh contracts`
is only the fast configuration/architecture gate. Missing tools or fixtures
fail acceptance; integration skips in ordinary unit tests do not constitute
system acceptance.

`scripts/build-system.sh` builds bounded local images with pinned bases and a
frozen web lockfile. It writes the binary hash, source state and actual image
IDs to ignored `.work/artifacts/manifest.json`. Neither this command nor test
success publishes images, deploys production, changes DNS or accesses a cloud
tenant. Use the [acceptance template](docs/verification/acceptance-template.md)
to record these separate gates outside the source repository.

Compose only runs prebuilt images and contains no build declarations. Build in
CI or with the separate build script, then load or pull the approved artifacts
before deployment. Set the required image references in `.env`; the example's
local tags are for development and production requires approved immutable artifacts.
