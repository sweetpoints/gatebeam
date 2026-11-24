# Gatebeam

Gatebeam is an ingress gateway with an independent Nginx data plane,
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

The root [VERSION](VERSION) file declares the Gatebeam product version using
[SemVer 2.0.0](https://semver.org/). Set it explicitly when preparing a release.
The declaration includes any pre-release and build metadata and is recorded
verbatim in the image version label and build manifest.

A push to `main` that advances `VERSION` triggers a release. Both native
Linux jobs must pass all twenty gates before they push the exact tested
images by digest to `ghcr.io/sweetpoints/gatebeam-{edge,api,worker,ca,query}`.
The workflow then writes and verifies a two-platform index for each role.
An existing version with different content fails the release. No image
archives or test outputs are uploaded between jobs.

GHCR tags use the declared version with `+` replaced by `_`. A tag that
would exceed the registry's 128-character limit uses `version-sha256-`
followed by the hash of the full version. The index and image metadata retain
the original SemVer. For first publication only, set each of the five GHCR
packages to Public in GitHub package settings. The workflow verifies anonymous
pull access before reporting success. After setting visibility, rerun the
failed publication job to verify the existing indexes without rewriting them.

Deployment files have separate purposes:

| File | Purpose |
|---|---|
| `compose.yaml` | Five runtime services per gateway node, using prebuilt images |
| `.env.example` | Example of the environment for one node, with image digests and node-specific settings |
| `compose.dev.yaml` | Standalone disposable development database |

Production uses two gateway VMs, with one independently managed Compose project
per VM and shared external PostgreSQL through Cloud SQL. The two management
replicas serve one logical console. Each gateway runs these roles:

| Service | Responsibility |
|---|---|
| `nginx` | Public HTTP/HTTPS entry and local configuration supervisor |
| `management` | Management web console and API |
| `background-jobs` | Renewal, probes, archival, notifications and backups |
| `internal-ca` | Standard internal ACME/OCSP/CRL authority |
| `log-query` | Resource-limited local/R2 historical log queries |

For first installation, follow the [deployment runbook](docs/operations/deploy.md)
to prepare the shared database, both nodes and their retained storage before
starting Compose. For updates, use the [dual-node deployment and upgrade
procedure](docs/operations/multi-instance.md).

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
before deployment. The production environment for each node must reference
approved images by digest.
