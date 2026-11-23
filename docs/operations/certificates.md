# Ordinary certificates and trust material

The certificates application owns persistent certificate specs, ACME accounts,
Cloudflare credentials, trust bundles and immutable certificate versions. Its
management constructor accepts the identity/ingress authorization adapters and
two distinct age public recipients. Sensitive writes require current administrator MFA, check
all affected draft and published references, and append audit in the same
transaction. The management console exposes HTTP adapters over these owning application contracts.

Use two independent age identities: one for leaf private keys and one for ACME
account keys, EAB HMACs and Cloudflare tokens. These are also separate from the
identity encryption key and every CA/root/status signer. `NewEdge` loads only the
leaf identity; it has no issuer adapter and its repository does not select
provider ciphertext. `NewWorker` loads only the provider identity and seals new
leaf keys to the leaf public recipient. `NewManagement` accepts both public
recipients, so API management can seal imports and credentials without decrypting
either. Returned resources contain metadata only. Assemblies reject equal age
recipients even when the same private key was copied to different file paths.

Configure the edge with:

```json
{
  "certificate_identity_file": "/run/gatebeam/leaf.agekey",
  "certificate_provider_recipient": "<provider public age recipient>",
  "acme_webroot": "/var/lib/gatebeam/acme-http01",
  "certificate_status_profiles_file": "/run/gatebeam/certificate-status.json"
}
```

Configure the worker with:

```json
{
  "certificate_provider_identity_file": "/run/gatebeam/providers.agekey",
  "certificate_recipient": "<leaf public age recipient>",
  "acme_webroot": "/var/lib/gatebeam/acme-http01",
  "certificate_status_profiles_file": "/run/gatebeam/certificate-status.json"
}
```

The API can load the public status profile file and both public recipients;
it never receives either certificate identity file. The status profile file is
needed only when trust references require it. Worker rejects a configured leaf
identity and edge rejects a configured provider identity. Do not mount the
provider identity into edge or either identity into API.

Apply the embedded `db/roles` goose migrations using the explicit migration
configuration (`migrate_roles: true`), then provision separate service logins
with their role-scoped capabilities. The edge role grants revision metadata
columns without `secret`, leaf-version reads and watermark UPDATE needed for
PostgreSQL row locking. It does not grant issuance/preparation writes or challenge
receipt access. Remove obsolete broad certificate runtime-role membership from
edge logins. The worker owns provider secret reads and issuance writes; API
management has write/seal authority. These roles grant no PKI table access.

For an existing installation that used one shared identity, stop old workers
before migration 00014. Keep that legacy identity worker-only to read immutable
provider credential history. Generate a fresh leaf identity, configure the new
worker with its public recipient, and issue fresh current leaf versions before
switching edge to the fresh identity. Imported replacements need a new spec
revision and publication. If the required fresh leaf version is absent, edge
cannot decrypt the legacy version and activation fails closed. Do not rewrite
immutable history or temporarily give edge the legacy identity to bypass the
transition. Previously exposed ciphertext retains its original decryptability;
this change does not revoke a private key or token already copied elsewhere.

The worker uses fixed public ACME directories for Let's Encrypt, ZeroSSL and
Google, standard EAB when supplied, and lego HTTP-01 or DNS-01. It never accepts a
business-supplied directory URL. For HTTP-01 set the same absolute `acme_webroot`
on worker and edge and mount the same directory writable by worker and readable
by Nginx. Port 80 must reach this local Nginx. DNS-01 supports multiple explicitly
scoped Cloudflare zone credentials. It writes only TXT challenge records. A
durable receipt stores the public TXT value and unique owner marker before
creation; restart cleanup checks the exact value/owner before deletion and never
removes an unrelated TXT at the same name. Keep historical encrypted credential
revisions available for cleanup. The cleanup wait is two minutes, longer than
the bounded issuance operation. Only public TXT content is recorded, never key
authorization or API tokens.

Creating/enabling an ACME spec authorizes first issuance before publication;
creating/enabling a trust bundle authorizes status preparation. Worker scans at
most 20 due current resources, with durable leases/backoff, outside network-free
authority transactions. The console explicitly labels creation/enabling as background preparation. Draft
routing edits do not trigger issuance. Material preparation runs independently
of the health/DNS worker loop and shares a bounded cancellation deadline.

Normal renewal starts at the last third of certificate lifetime. A persistent
spec-wide lease prevents writers across published/current revisions; separate
revision failure backoff survives
restart. Failure leaves the previous usable version in place. Automatic material
activation rereads the current published snapshot and current security material
under the existing activation lock order; the original human publisher's session
is not required. It preserves unrelated drafts. Name, purpose and pinned trust
changes create a spec revision that requires publication. Imports have no
automatic renewal; replacing an imported version requires a new spec revision
and publication. Immutable material artifacts remain referenced by each local
Nginx generation and pass syntax/reload checks before activation.

For trust requiring OCSP/CRL, set `certificate_status_profiles_file` in API,
worker and edge to the same operator-owned JSON array. Each profile contains
`id`, `fingerprints` (SHA-256 certificate DER hex), `crl_urls` and `ocsp_urls`
mapped by fingerprint, `allowed_networks` and `resolver_servers` (IP:port). Use
actual issuer endpoints and existing trusted private/GCP DNS infrastructure.
No DNS server is introduced. The adapter resolves and pins allowed addresses,
verifies standard signatures, CertID issuer binding, responder identity,
delegation, validity and CRLs, and caches a bounded attestation. A signed Unknown
for a random unknown serial establishes responder readiness only; it never says
an actual certificate is Good. Known intermediates require Good; native Nginx
checks actual client certificates. Expired/unavailable evidence fails closed at
activation. P6 covers complete native business client enrollment/revocation.

Cloudflare address authority belongs to deployment. Worker reads the official
IP endpoint every five minutes with a one-hour validity ceiling. A fetch failure
retains only a still-valid cached set; known removal or expiry closes affected
sites. The compiled volatile `$msec` map also denies new CF-site requests after
its fixed conservative deadline even if worker or database is unavailable and
no reload occurs. Other sites continue. This does not disconnect already admitted
streams. Both IPv4 and IPv6 user allowlists are intersected with the official set;
empty intersection never means allow-all.

Run `scripts/check-pki.sh public-client` for the owned standard CA, stub Cloudflare
API/status DNS, and real cached Nginx fixtures. It builds a fresh Linux edge
binary. No real Cloudflare mutations or public certificate requests are made by
these tests. Full PKI integration additionally needs a fresh `pki-native` fixture
and `GATEBEAM_TEST_OPENSSL` pointing to OpenSSL 3.


## Management console and public receipts

Open `/console/certificates`, `/console/credentials` and
`/console/identities`. Set API `certificate_recipient` (leaf public age recipient)
and `certificate_provider_recipient` (provider public age recipient); never mount
either private identity in API. Internal enrollment also requires the independent
CA public `ca_recipient`, trusted HTTPS `ca_origin`, and server/client policy names.
The API does not load `NewServer`, issuer/root/status keys, provider/leaf private
identities or ACME network adapters. Existing private CF credentials, private leaf
keys, TOTP seeds and existing EAB HMACs have no read endpoint.

`GET /certificates/{spec|account|credential|trust}` and the corresponding `/{id}`
return safe metadata under current credential checks. A resource requires View on
**every** affected draft and published site, including indirect account, credential
and trust dependencies across all immutable spec revisions. Unreferenced resources
require an interactive global administrator; a site-limited admin-owned API token
cannot read global/unreferenced resources or `/pki/management`. Writes retain the
existing current interactive administrator + fresh single-use TOTP boundary, scope
and expected-revision checks, with audit in the owner transaction. GET never consumes
TOTP. Lists are bounded to 1000 current resources; version metadata is bounded to the
latest 100 versions. No private material reference is returned.

The console distinguishes the **current stored version** of the current management
spec revision from the exact **last verified native material binding**. Migration
00016 adds public binding metadata to the deployment-owned current runtime receipt.
Publication, derived application and recovery save spec/ref revision, immutable
version ID/digest and the exact artifact/version/generation/time in the same final
verified transaction. No PEM, DER, keys, ciphertext or raw runtime serialization is
stored in that receipt. Existing receipts have empty bindings and remain unconfirmed.
The compiler records public certificate refs only at actual `ssl_certificate` /
`proxy_ssl_certificate` emission; a root-prefix route that suppresses a default
location and an all-unhealthy target with only `return 503` do not confirm an
unused client identity. Other emitted routes/sites may still load the same
certificate. A maintenance server-level return does not remove TLS directives
that are physically emitted/loaded. Selection refs and content digest are both
checked at final authority; private files are never parsed to infer activation.
A newer draft may have no stored material while an older published spec revision is
still active. `lifecycle.revisions` keeps current-management and exact verified
revision retry state separate: revision1 failure/backoff remains visible while
unpublished revision2 has zero failures. Top-level retry fields continue to refer
only to the current management revision. A new stored renewal with the old verified binding is pending native
application; failure/backoff never manufactures an active success. A binding is the
last actual verification, not a continuous liveness guarantee. If the gateway is
stopped or a later network probe fails, inspect current operational evidence.

Use POST/PUT `/certificates/{kind}` for explicit create/replace-and-enable and POST
`/certificates/{kind}/{id}/enabled` for state changes. Replacement requires exact
`expected_revision`; enabling authorizes worker preparation, never synchronous
ACME, status probes or publication in the API request. Import through
`POST /certificates/spec/{id}/import` only targets import specs. A replacement
requires a new spec revision and manual publication; imported material never auto
renews. Secret input fields clear after each attempt or navigation, including full
page navigation. EAB is shown only in its create response, outside Query/Pinia and
browser storage; dismissing or navigating clears it. Reissue invalidates the old
EAB; standard ACME consumes it once. Identity disable blocks future issuance;
individual certificate revocation is a separate audited action with normal
OCSP/CRL cache semantics.

Cloudflare AOP is independent third-party trust. Import and check the official or
operator-owned trust bundle, configure trusted status policy, and manually enable
and verify the matching Cloudflare dashboard feature for the domain/account and
current plan. This API only manages gateway resources; it does not enable Cloudflare
account features or change a Cloudflare plan.

Apply versioned capability grants from `db/roles` with `migrate_roles: true`
using the migration owner during upgrade; these include preparation metadata
and public order-purpose column access. Runtime/API startup does not grant privileges.

`GATEBEAM_BROWSER_CHANNEL=chrome ./scripts/check-web.sh pki` builds the actual Linux
edge and uses disposable Chrome, PostgreSQL, native Nginx, owned standard ACME CA
and the ordinary lego worker. It covers create/enrollment, one-time EAB, multi-zone
credential secrecy, prepublication issuance, exact native receipts, pending/new
renewal, real TLS certificate observation, CA outage, separate disable/revoke/audit,
and scoped current-authority reads. It does not call public CAs, Cloudflare, email,
Telegram, SSH or production. O6 retains actual production-worker shared webroot,
DNS-01, capacity and time-budget acceptance; P7 does not replace those gates.


### Current leaf status

Publication, activation, final receipts, derived updates and restoration validate selected certificates against the owning PKI public status projection. Identity is SHA-256 of the verified issuer SPKI plus padded serial and SHA-256 of the exact leaf DER. Imported certificates with a known local issuer key obey the same good-only policy; external issuer keys retain the existing imported/public-CA validation policy. Missing, unknown, quarantined and revoked local records are unavailable even when route health checks are disabled.

`pki_leaf_status` is an owner-executed security-barrier view containing only issuer key fingerprint, serial, leaf fingerprint and state. Runtime API/edge/worker roles receive SELECT on that view, with no leaf DER, signing or mutation grant. CA has only the additional `UPDATE(key_fingerprint)` capability. Apply the current Goose migrations and maintained role changes before starting the new binaries. The CA registry refreshes up to 1024 missing issuer fingerprints from already stored public DER, including retired issuers without their private keys. Missing/invalid metadata or a larger unclassified backlog fails closed; resolve the public registry metadata before enabling material selection.

New certificate versions persist verified issuer/leaf identities and the worker's immutable enrollment provider. Older versions did not pin account revisions and cannot safely derive enrollment provenance from a mutable account. Renew automatic versions with the standard client, or create and import a fresh revision for imported versions, before republishing them. `Ensure` renews legacy automatic versions lacking identity/provenance metadata. Conservative recovery preserves these public identities but quarantines old issuers; it never makes a restored leaf good. Restore rebuilds the view from migrations and verifies the snapshot schema digest.

The transaction lock order is identity, ingress, certificate watermark, PKI shared status fence, then deployment receipts. Revocation takes the exclusive PKI status fence after its principal/account checks and never acquires ingress/certificate/deployment locks. Registry refresh and quarantine use the same exclusive fence; the isolated recovery coordinator acquires certificate quarantine locks first. Native route probes run outside these transactions, followed by a fresh status decision before the final receipt.
