# First deployment

Gatebeam production runs on two gateway VMs in the same GCP zone. Each VM
runs one independent Compose project with the five Gatebeam roles. Both
nodes use external PostgreSQL on Cloud SQL. The two management replicas
serve one console with shared account and session state.

The [dual-node deployment and upgrade runbook](multi-instance.md) is the
authoritative procedure for node provisioning, initialization, activation
and rolling upgrades. Use it to fill in the node manifests and configuration
for the target environment.

## Prepare the release images

1. Check out the approved exact source commit in a clean checkout. Use
   Go 1.27 and select the Linux image architecture that matches the target.
2. Run `scripts/build-system.sh` to build the five images from source and the
   frozen web lockfile. Retain the declared version, source commit, binary
   hash and image IDs from `.work/artifacts/manifest.json` with the acceptance
   evidence.
3. Publish the approved images to the registry used by the target nodes and
   record the resulting registry manifest digests. Use these digests for the
   five `GATEBEAM_*_IMAGE` settings in each node's environment. Pull the approved
   images before starting Compose. Production Compose uses prebuilt images.
   GitHub acceptance currently builds and tests images locally on each Runner.

The [example environment](../../.env.example) shows the variables for one
node. Its image digests, addresses and paths are placeholders. Each node
requires its own environment file, Compose project, retained storage and
role-specific secrets. [compose.dev.yaml](../../compose.dev.yaml) starts a
disposable development database in a separate Compose project.

## Initialize the deployment

1. Prepare the public and private GCP load-balancer backends, private DNS and
   firewall rules, Cloud SQL connectivity, and retained runtime and log
   storage. The dual-node runbook specifies the health endpoints and port
   bindings. Keep role health ports on the private network.
2. Run the schema and role migrations explicitly against the shared database
   using the protected migration configuration. Use separate limited database
   identities for each node and role. The runtime services load their own
   credentials. The query role has no database login.
3. Prepare each node's identities, render its five role configurations and
   environment, and provision and verify its retained storage. Set up the
   management TLS material and private trust, and follow the
   [offline CA ceremony](pki-bootstrap.md) for the internal CA. Keep the
   root private key offline.
4. Register each node, initialize edge with `--initialize-edge`, and confirm
   the local boot artifact. Start the five services using the node's Compose
   environment and `--no-build`. Once both nodes are ready, run
   `gatebeam-admin --operation activate-nodes` using the node-admin
   configuration and the two registered manifests.
5. Verify the management console, both nodes' public and private entry paths,
   mTLS, and the configured certificate, logging, backup and notification
   providers. Use the [gradual migration procedure](gradual-migration.md) for
   the existing sites and record target-environment results in the
   [acceptance template](../verification/acceptance-template.md).

Use the rolling upgrade procedure in the dual-node runbook for an existing
deployment. Use the [isolated recovery procedure](backup-restore.md) for
backup restore. Keep deployment, upgrade and recovery credentials separate
from the running roles.
