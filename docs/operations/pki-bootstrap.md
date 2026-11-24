# Private CA bootstrap

For CA management and new CA provisioning, see the
[CA module](../../gatebeam-ca/README.md).
Gatebeam no longer exposes CA operator actions in its API or console. The
gateway Compose deployment uses the CA image as a separately operated service.
The embedded CA commands below describe the historical deployment. Its
legacy certificate publication policy reads the local CA ledger.
To validate publication and distribution against an independently deployed CA,
set `certificate_status_trust_file` on both the management API and edge. The PEM
contains the CA root and the issuing intermediates. Configure their pinned
responder URLs, DNS resolvers, and allowed networks in
`certificate_status_profiles_file`. Gatebeam verifies a fresh signed CRL and
a Good OCSP response for each non-root certificate in the chain. The gateway
does not connect to the CA database in this mode.

For management API transport certificate renewal against a separate CA, set
`private_tls_renewal.http01_webroot` to a dedicated writable absolute directory.
Serve `/.well-known/acme-challenge/` from this directory on the private DNS
hostname in the management certificate. Every management renewal client needs
its own hostname and directory. Keep the business challenge webroot separate.
This option uses the local HTTP-01 responder instead of the shared challenge
table for management renewals.

The private CA supplies an offline issuer ceremony, immutable public issuer
storage, and standard ACME v2 account enrollment using EAB. Both directories
support newNonce, newAccount, account POST-as-GET/update/deactivation and
keyChange. Orders, authorizations, HTTP-01 challenges, finalization, account order lists
and certificate retrieval are implemented. Revocation is available through standard
ACME HTTPS. CA operators administer the standalone CA using its CLI. OCSP and CRLs are available on
the separate private HTTP status listener. There is no generic JSON CSR issuance API.

## Offline ceremony

Run `gatebeam -config /absolute/path/offline-bootstrap.json` on the offline
ceremony host. The configuration contains paths and public names only:

```json
{
  "environment": "production",
  "mode": "ca-bootstrap",
  "offline_root_directory": "/offline/gatebeam-root-v1",
  "ca_output_directory": "/transfer/gatebeam-online-v1",
  "ca_root_name": "Operator chosen offline root name",
  "ca_intermediate_name": "Operator chosen online issuer name",
  "ca_status_origin": "http://status.internal.test:8081"
}
```

Both output directories must be new absolute paths, with existing parents; they
must not overlap or contain one another. Creation never overwrites existing
material. Directories have mode 0700, files 0600, and successful output is fsynced,
including parent directories. Failure removes only directories this invocation
created. Success prints no keys, certificates or CSRs.

The root directory contains a standard PKCS#8 PEM private key (`root-key.pem`)
and X.509 PEM certificate (`root.pem`). Keep that directory offline; never copy
or mount it into API, worker, edge or CA services. The generated P-384 root has a
ten-year lifetime and path length one. The distinct P-384 intermediate has a
one-year lifetime and path length zero. Changing authority requires a new
explicit ceremony; this command does not silently rotate an existing root.

Only the online directory is transferred to the CA host. It contains the public
`root.pem` and `issuer.pem`, an age encrypted PKCS#8 PEM signer (`issuer.age`),
public root CRL (`root.crl.der`), a public root OCSP delegate certificate
(`root-ocsp.pem`) and its separately labelled encrypted key (`root-ocsp.age`), and
a dedicated CA age identity (`identity.agekey`) and its public X25519 age
recipient (`recipient.txt`). Only the recipient string may be copied to API
configuration; the API cannot decrypt EAB ciphertext with it. The encrypted payload uses F1's
labelled secret store with label `pki-online-issuer`. This age identity must never
be shared with the API identity, packaged into images, or mounted into other
processes. Restrict these files and the destination directory to the CA OS user.

## CA process configuration

Provision a separate CA database login after applying all embedded migrations. As the
migration owner, run the embedded `db/roles` goose migrations with
`migrate_roles: true` and the deployment schema selected in `search_path`; grant schema USAGE and the `gatebeam_pki_ca` capability role to
the CA login. The gateway API login has no CA enrollment or administrative
revocation privileges. These roles contain no passwords. Do not use
an owner/superuser login or grant broad table privileges to runtime processes.
The CA startup checks read/append privileges and rejects mutable issuer or
serial authority. The API capability can read public issuer metadata but cannot
insert certificates, reserve serials, update or delete issuer records.

Configure the actual internal FQDNs explicitly. The names below are reserved
examples and must be replaced with the operator's chosen internal names; no DNS
or cloud records are created by Gatebeam.

```json
{
  "environment": "production",
  "mode": "ca",
  "database_file": "/run/secrets/ca-database",
  "ca_listen": "127.0.0.1:8443",
  "ca_hostname": "ca.internal.example",
  "ca_status_origin": "http://status.internal.test:8081",
  "ca_status_listen": "10.20.0.2:8081",
  "ca_root_crl_file": "/run/ca/root.crl.der",
  "ca_root_ocsp_certificate_file": "/run/ca/root-ocsp.pem",
  "ca_root_ocsp_signer_file": "/run/ca/root-ocsp.age",
  "ca_origin": "https://ca.internal.example:8443",
  "ca_tls_certificate_file": "/run/ca-transport/server.pem",
  "ca_tls_key_file": "/run/ca-transport/server-key.pem",
  "ca_certificate_file": "/run/ca/issuer.pem",
  "ca_root_file": "/run/ca/root.pem",
  "ca_signer_file": "/run/ca/issuer.age",
  "ca_identity_file": "/run/ca/identity.agekey",
  "ca_server_names": ["backend-a.internal.example"],
  "ca_client_names": ["gateway.internal.example"],
  "ca_validation_networks": ["10.40.2.0/24"],
  "ca_validation_deny_networks": ["10.40.2.1/32", "10.40.2.10/32"]
}
```

The listener requires an explicit private or loopback IP and nonzero port; it
rejects wildcard/public binds. Production operators select the reachable private
address and network rules. Bootstrap TLS uses separately provisioned standard
server certificate/key files, with current validity, the configured hostname
and serverAuth. Install that transport certificate's trust anchor in standard
ACME clients out of band. The listener does **not** require a client certificate:
initial enrollment cannot depend on an already-issued business mTLS leaf. A
handshake verifies bootstrap reachability only; account interoperability is
verified separately against a local standard client. The CA must not be published through business-leaf mTLS gates.

The online loader validates a direct, currently valid root/intermediate chain,
CA constraints, certSign/CRLSign, both supported leaf purposes, private-key match,
and a distinct root public key. A root key rewrapped in another certificate is
rejected. Only explicit exact DNS names are allowed; wildcards, IP SANs,
unauthorized names, CA requests and requester-controlled EKU are rejected.
ServerAuth and clientAuth remain separate policies at the standard directory
paths `/acme/server/directory` and `/acme/client/directory`.

The signing primitive is internal infrastructure and is not exposed by a
handler. ACME finalization authorizes and locks the order, reserves a
positive random serial (at most 159 bits; 40-character lowercase padded hex in
storage), signs, and persists the certificate in one authority transaction before
returning it. A unique `(issuer_id, serial)` database key protects collisions;
Retries return the same stored certificate after rechecking the current principal
and account key. Disabling a principal blocks pending and completed resource access.
Revocation is a separate synchronous operation; see the standard revocation section below.

## Verification

Unit checks: `go test ./internal/modules/pki/... -count=1 -p 2 -timeout 90s`.
Real PostgreSQL and process integration checks:

```sh
GATEBEAM_TEST_OPENSSL=/absolute/path/to/openssl \
  sh scripts/check-db.sh ./internal/modules/pki/... ./internal/composition \
  -run 'Test(IssuerImmutability|CARole|OpenSSL|CAProcess)' -v
```

The test creates bounded, owned PostgreSQL 18 fixtures and runtime-only keys.
OpenSSL independently verifies standard CSR DER, PKCS#8 PEM public-key matching,
chain validation, and acceptance/rejection of the distinct server/client EKUs.
It does not establish production readiness or Nginx/ACME interoperability.

## First explicit enrollment grant and one-time EAB

CA operators use the [CA module](../../gatebeam-ca/README.md)
for enrollment authority. Use `gatebeam-ca authorize` and `gatebeam-ca issue-eab`
to grant exact DNS names and create one-time EAB. Enter the KID and HMAC into
the Gatebeam ACME client configuration for the matching server or client
directory. The gateway's certificate and credential screens manage the local
ACME client account and certificate lifecycle.

The first successful newAccount consumes EAB atomically. Subsequent
account operations use the registered account key. Use `gatebeam-ca disable`
to stop future authorized operations for a principal. Use `gatebeam-ca revoke`
to revoke an already-issued certificate.

The CA validates the protected URL against `ca_origin` and the exact request
URI. Configure the real client-facing HTTPS origin explicitly; request Host or
forwarded headers cannot choose it. Requests are bounded to 64 KiB; supported
account signature algorithms are RS256 (2048–4096-bit RSA), ES256 and ES384.
EAB uses HS256. Nonces expire after ten minutes, are consumed in a separate
committed transaction after signature verification, and remain spent when
later business validation or account persistence fails. Issuance performs a
bounded cleanup of at most 128 expired nonce rows per new nonce.

Run account and actual unmodified lego interoperability tests against an owned
PostgreSQL fixture and local HTTPS endpoint:

```sh
./scripts/check-db.sh ./internal/modules/pki/application/acme/... ./internal/composition/... ./internal/modules/pki/infrastructure/postgres/...
```

These tests never register against a public or production CA. They cover account lifecycle and issuance transactions. Native client verification
is run separately below. Apply the role SQL using the schema owner; runtime never grants itself
additional privileges. The CA may read enrollment policy, consume bindings,
maintain account keys/status and manage nonce rows, but cannot create or widen
principals/grants/EAB. The API cannot manage enrollment authority or
write ACME account keys, issue certificates, or reserve issuer serials.

## HTTP-01 network policy and durable issuance

Both directories require a real challenge response at
`http://<identifier>/.well-known/acme-challenge/<token>` on TCP port 80. A human
EAB grant does not satisfy domain control. Use a distinct FQDN and persistent
ACME state directory for each A/B instance; do not share account state paths.
The client directory also validates its granted DNS identifier using HTTP-01.

`ca_validation_networks` is a required, explicit list of private CIDRs. Include
only the networks containing authorized challenge listeners; exclude database,
metadata, management and other control services using
`ca_validation_deny_networks` and network firewall rules. The CA's own bound
listener address is denied automatically. Loopback, link-local, public, multicast
and shared-address-space targets are rejected even when configured. The
[AWS IPv6 IMDS](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html)
and [Google IPv6 metadata](https://docs.cloud.google.com/compute/docs/metadata/querying-metadata)
ULA endpoints are also denied unconditionally. Every DNS
answer must be allowed before a connection is made. Connections use a checked
IP directly, retain the original Host, and ignore proxy environment variables.
At most three redirects are followed, only on the same authorized DNS name and
HTTP port 80. HTTPS and cross-host redirects are rejected. Each hop resolves and
validates all answers again. Response size and total validation time are bounded.

Validation holds no database transaction or lock during network I/O. Completion
locks the principal again, checks current grant/account status and account key
revision (including a key changed away and back), then checks the challenge
revision. Failed or expired proofs cannot be revived. Different identifiers in
one order can complete concurrently. Finalization requires every challenge to
be valid and the exact CSR SAN set to equal the order; it verifies the CSR
signature and rejects requested CA, EKU and other unsupported extensions.
The directory fixes serverAuth versus clientAuth; no custom profile/header is used.
Leaves have a 24-hour maximum lifetime. A valid order is completed atomically
with its positive unique serial reservation and immutable DER/PEM chain record.
A failed commit cannot expose certificate bytes or an OCSP good response.
The management role has only certificate metadata column reads, never DER writes.

Run the complete PKI suite, including actual unchanged Nginx and lego clients:

```sh
GATEBEAM_TEST_OPENSSL=/absolute/path/to/openssl ./scripts/check-pki.sh acme
```

Docker must already have PostgreSQL 18 and the official Nginx image
`nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606`
(Nginx 1.31.8, bundled ACME module 0.4.1). Set `GOARCH` to the Docker engine's
architecture if it differs from the default arm64. The script builds the current
source's Linux test fixture. This uses the production ACME application,
PostgreSQL adapters and P1 signer under a restricted CA role, with a test-only
45-second signing lifetime to observe real automatic renewal in bounded wall
time. It does not alter clocks, bypass TLS, substitute Pebble, or modify clients.
The offline root private key stays outside every container mount. Tests use
isolated A/B FQDNs/state, real port 80 challenges, server/client lego issuance,
negative name and missing-proof requests, trusted TLS, automatic renewal,
automatic renewal after the CA restarts, and CA-offline Nginx restart.
All owned containers, networks and temporary keys are cleaned up. Logs and
agent reports are not product artifacts and must not be committed.


## Standard revocation and status

The CA's HTTPS listener exposes ACME, including `revokeCert`. Its separately
configured private HTTP listener exposes `/ocsp` (POST), `/ocsp/{base64-DER}`
(GET), `/crl/{issuer-fingerprint}.der`, and `/crl/root.der`. It does not expose
ACME account/order operations or management API routes. Both listener IPs must
be included in the HTTP-01 control-network exclusions. OCSP and CRL responses
are public signed material; no private key or management credential is returned.
The configured canonical `ca_status_origin` supplies leaf AIA and CRLDP URLs.
The same origin is required during offline bootstrap to put standard OCSP AIA
and root CRLDP into the intermediate certificate. Runtime rejects an intermediate
whose AIA does not match this configured endpoint.
CSR-provided URLs and extensions are not copied.

CA operators revoke certificates with the standalone `gatebeam-ca revoke` command.
Revocation and its CA audit record commit in one database transaction. Disabling a principal prevents further issuance
and is separate from revoking already issued leaves. ACME revocation permits the
current issuing account, a current account with unexpired validated challenges
for every certificate identifier, or a JWS signed by the certificate key. Account
paths recheck current principal policy and account key under the same principal
lock protocol as issuance. A certificate-key holder can still revoke after its
principal was disabled. Reasons 0, 1, 3, 4, 5 and 9 are supported; hold/removal and
CA-only reasons are rejected with `badRevocationReason`. Revocation is terminal;
repeated ACME requests return `alreadyRevoked`.

The OCSP CertID is matched against the actual issuer subject and subject-public-key
hash, then the issuer-qualified serial. Unknown certificates return `unknown`;
unrecognized issuers never receive `good`. A distinct leaf-status delegated OCSP signing key
and certificate are generated in the CA, used with only OCSPSigning EKU, and
rotated before expiry. Public responder certificate/serial reservations are
persisted; the delegated private key is memory-only and changes after restart.
Responses have five-minute `nextUpdate`, bounded by the validated signer and
issuer lifetime; restart does not reset leaf revocation state. CRL numbers are
persistently increasing and every generated issuer CRL contains the full
permanent revocation set. CRLs expire after one hour or issuer expiry, whichever
is sooner. These are normal cache/freshness windows, not a one-minute SLA.
Neither revocation nor disable is claimed to terminate existing connections.

## Full-chain OCSP with offline-root delegation

Native client validation uses `ssl_ocsp on`, covering the entire client chain.
The offline ceremony additionally issues a distinct non-CA OCSPSigning certificate
directly from the root and encrypts its separate key to the CA identity with label
`pki-root-ocsp`. This is the standard issuer-direct delegation in
[RFC 6960 section 4.2.2.2](https://www.rfc-editor.org/rfc/rfc6960.html#section-4.2.2.2).
Neither the root CA key nor its signing capability is loaded online. The root
OCSP credential has digitalSignature only, OCSPSigning only, and a one-year
initial lifetime aligned with the intermediate; it cannot issue certificates.
API configuration forbids its private-key path as well as the intermediate key.

Root status responses require the exact registered public intermediate and a
current valid root CRL. An unknown root-issued serial is `unknown`; a listed
revoked serial is `revoked`. Root responses are generated fresh with at most five
minutes of validity, further bounded by the root CRL, root certificate and
root-delegate expiry. The private root delegate persists encrypted across CA
restarts because renewal requires the offline root. Its root-qualified serial
and the intermediate's serial are reserved against collisions before serving.
The delegate itself being listed on the root CRL disables its status signing.
No OCSP NoCheck extension or custom client behavior is used.

The database remembers the accepted root CRL number, exact DER and observed
revoked serial set. A lower number, changed bytes with the same number, or a
newer CRL that forgets a previously observed revocation is rejected. This protects
ordinary file publication/restart; restoring the authoritative database from an
older backup still requires O6's restore safety procedure and issuer state
reconciliation. A CRL cannot represent unknown inventory after data loss.

Before root-delegate expiry, renew its public certificate in the offline root
ceremony. Its existing encrypted private key can stay on the CA; export only the
public certificate to the offline machine. For example, with OpenSSL 3.5, create
`root-ocsp-extensions.cnf` containing:

```ini
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,OCSPSigning
```

Extract that delegate's public key and use a new positive root-qualified serial
tracked in the offline ceremony inventory. The following uses a fresh 152-bit
random serial; online registration also rejects a collision with any registered
root-issued intermediate/delegate:

```sh
openssl x509 -in root-ocsp.pem -pubkey -noout -out root-ocsp-public.pem
openssl x509 -new -force_pubkey root-ocsp-public.pem \
  -subj '/CN=Root OCSP delegate' -CA root.pem -CAkey root-key.pem \
  -set_serial "0x$(openssl rand -hex 19)" -days 365 \
  -extfile root-ocsp-extensions.cnf -out root-ocsp-next.pem
```

The new validity must fit inside root validity. Review subject, key, EKU,
constraints, serial and dates before transferring only the new public certificate
to a new online file. Keep the matching encrypted `root-ocsp.age`, update
`ca_root_ocsp_certificate_file`, and restart the CA to validate and register it.
For private-key replacement, use a new offline-created delegate/key encrypted to
the CA recipient with the same labelled secret format, and retire the old
credential through the preserved root CRL inventory. Never copy `root-key.pem`
into an online directory. Expired/missing credentials fail closed; there is no
automatic online root delegation renewal.

## Offline root CRL ceremony and renewal

Bootstrap exports `root.crl.der` into both directories. The initial signed root
CRL has number 1 and a 30-day validity. Transfer only its public copy to the CA.
The online process never reads the root private key. Before starting either
listener it verifies the offline CRL's signature, freshness and that its issuer
intermediate is not revoked. `/crl/root.der` keeps publishing a valid signed root
CRL even if it lists the intermediate as revoked; clients must receive that fact.
Missing, invalid or expired root CRLs are unavailable, never fabricated as empty.

On the offline root host, maintain a persistent OpenSSL CA index and CRL number
file. For the first adoption of a freshly bootstrapped root only, create a new
empty `index.txt`, a `crlnumber` containing `02`, and this `openssl.cnf` beside
`root.pem` and `root-key.pem`. Never reset an existing index or counter:

```ini
[ca]
default_ca=root
[root]
database=index.txt
crlnumber=crlnumber
certificate=root.pem
private_key=root-key.pem
default_md=sha384
default_crl_days=30
```

Import the public intermediate certificate once into that offline database,
then issue later CRLs using its preserved index and increasing counter:

```sh
openssl ca -config openssl.cnf -valid /offline/public/issuer.pem
openssl ca -config openssl.cnf -gencrl -out root-next.crl.pem
openssl crl -in root-next.crl.pem -outform DER -out root-next.crl.der
```

If the intermediate must be revoked, run the standard `openssl ca -revoke`
ceremony against its public certificate, with the appropriate standard reason,
before `-gencrl`. Review the resulting issuer, CRL number, dates and signature;
transfer only `root-next.crl.der`. Preserve the offline index/counter with root
custody records. Replace the online public CRL file atomically and restart the CA
to repeat its startup safety check. Root/issuer recovery and backup rollback
remain fail-closed operational concerns; a CRL has no representation of an
unknown lost certificate inventory.

Publish gateway CRL bundles as immutable versioned material containing both the
intermediate-signed leaf CRL and the offline-root-signed intermediate CRL.
`proxy_ssl_crl` checks the full upstream chain. Missing root CRL must fail closed.
Switch the configuration to the new material generation, validate/reload Nginx,
and wait for old workers to exit before claiming the generation is active.
In-place same-second rewrites can preserve Nginx's inherited SSL object cache;
use new material files, as described by [Nginx SSL object inheritance](https://nginx.org/en/docs/ngx_core_module.html#ssl_object_cache_inheritable).

`GATEBEAM_TEST_OPENSSL=/path/to/openssl ./scripts/check-pki.sh status` runs real
PostgreSQL state/rollback/restart tests, standard OpenSSL offline CRL and delegate renewal and
unmodified Nginx native OCSP/CRL tests. Session cache and TLS tickets are disabled;
TLS 1.2/1.3 reconnect attempts cannot bypass a full new certificate check. This
is not a claim that already-resumed sessions were checked. P5 supplies actual
certificate/trust runtime bindings; P4 does not invent a production material
provider.

## Recovery quarantine

Migration 00020 adds permanent `pki_restore_quarantine`. Existing CA/API
capability roles receive its SELECT grant through the versioned `db/roles`
goose migrations (`migrate_roles: true`), without recreating existing roles.
Do not grant INSERT/UPDATE/DELETE/TRUNCATE to online roles. The isolated local
restorer owns entry creation, and CA startup refuses a quarantined issuer.
See [backup and conservative recovery](backup-restore.md) for the required offline
root revocation, new issuer and manual trust activation procedure. OCSP unknown
alone does not protect CRL-only clients from certificates issued after a backup.

## Existing-root intermediate and delegate rotation/import

Use this ceremony when renewing an intermediate, replacing its signing key, or
recovering from an unproved issuer watermark. Preserve the existing root trust
anchor and the complete offline OpenSSL ledger; `ca-bootstrap` is for a new
root, not this operation. Schedule any required outage before revoking an issuer.
For a fresh bootstrap's first ledger adoption only, import both `issuer.pem`
and `root-ocsp.pem` once with `openssl ca -valid`. Never initialize an empty
ledger or reset CRL numbers for a root that already issued other certificates.

Extend the offline `openssl.cnf` with a preserved `serial` counter,
`new_certs_dir`, signing policy and extensions. Initialize those paths only on
first adoption. Set each lifetime within the root's remaining validity. Use the
actual configured private status origin in AIA/CRLDP:

```ini
# Add within [root]:
# new_certs_dir=newcerts
# serial=serial
# default_days=365
# policy=policy
# unique_subject=no
[policy]
commonName=supplied
[intermediate]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
authorityInfoAccess=OCSP;URI:http://status.internal.test:8081/ocsp
crlDistributionPoints=URI:http://status.internal.test:8081/crl/root.der
[delegate]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,OCSPSigning
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always
```

On the offline host, create a new mode0700 `next` directory outside root custody,
then run under `umask 077` with explicit command deadlines appropriate to the
local ceremony (the tested software operations each fit a five-second bound):

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out next/issuer-key.pem
openssl req -new -key next/issuer-key.pem -subj '/CN=Next intermediate' -out next/issuer.csr
openssl ca -batch -notext -rand_serial -config openssl.cnf -extensions intermediate -in next/issuer.csr -out next/issuer.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out next/root-ocsp-key.pem
openssl req -new -key next/root-ocsp-key.pem -subj '/CN=Next root OCSP delegate' -out next/root-ocsp.csr
openssl ca -batch -notext -rand_serial -config openssl.cnf -extensions delegate -in next/root-ocsp.csr -out next/root-ocsp.pem
# Select the actual reason and reviewed old public certificate for this ceremony.
openssl ca -config openssl.cnf -revoke old/issuer.pem -crl_reason keyCompromise
openssl ca -config openssl.cnf -revoke old/root-ocsp.pem -crl_reason superseded
openssl ca -config openssl.cnf -gencrl -out next/root.crl.pem
openssl crl -in next/root.crl.pem -outform DER -out next/root.crl.der
cp root.pem next/root.pem
openssl verify -CAfile root.pem next/issuer.pem next/root-ocsp.pem
openssl crl -in next/root.crl.pem -noout -text
```

Normal expiry renewal may have different revocation reasons/timing; choose them
explicitly. Check the new root CRL's increasing number, complete retained revoked
set, issuer, signature and dates. Record exact root-qualified serials. The new
intermediate must not be revoked, and the new root delegate must be a distinct
root-direct non-CA OCSPSigning-only key/certificate, with current validity.

Import the six standard files in `next` using the maintained CLI on the offline
host. PKCS#8 private keys must be plaintext PEM readable only by the ceremony
operator; the root private key is not an input. Use absolute, separate source
and new output directories and serialize ceremonies targeting that output:

```json
{
  "environment": "production",
  "mode": "ca-import",
  "ca_import_directory": "/offline/ceremony/next",
  "ca_output_directory": "/transfer/online-epoch-next"
}
```

Run `gatebeam --config /offline/import.json`. Import verifies key matches,
issuer/root chain/purposes/current validity, delegate constraints and signed
fresh root CRL; it rejects existing output paths. It creates a fresh dedicated
age identity, labels/encrypts the intermediate and delegate keys, fsyncs and
publishes the new directory. It reads no root key, contacts no DB/network and
activates nothing. Transfer only that encrypted online epoch to the CA service;
securely retain/destroy ceremony plaintext according to root custody policy.

Update CA file paths and the API's public CA recipient together. Keep any old
issuer quarantined after an unproved restore; do not clear its quarantine to
reuse it. Register/start the new issuer under the actual restricted CA login,
publish the signed root CRL and current issuer CRL, and replace gateway trust/
revocation material through the explicit authenticated flow. Verify the old
intermediate is rejected under standard full-chain verification (including an
unknown post-backup leaf), the new issuer succeeds, and CA restart reloads the
persisted root delegate without accessing the root key. Standard native
ACME/OCSP/restart acceptance performs this ceremony with owned OpenSSL fixtures.
The process never automatically renews an offline root credential.

## Leaf validity policy and synchronized clocks

For a leaf signed at `signingNow`, NotBefore is
`max(issuer.NotBefore, signingNow - 60 seconds)` and NotAfter remains
`min(issuer.NotAfter, signingNow + configured lifetime)`. The 60-second bound is
an explicit engineering issuance policy for small clock/ASN.1-second boundaries;
it is not mandated by [RFC 5280 section 4.1.2.5](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.2.5).
Issuer/root validity, key, chain and purpose checks still use actual current time
and standard clients retain strict certificate verification. Synchronize host,
container runtime and client clocks; this policy is not a substitute for that
prerequisite. It does not reconstruct the cause of an earlier unrecorded clock
or SNI failure. Tests cover the issuer NotBefore clamp, unchanged expiry,
future/expired issuer rejection and strict verification at the actual test time.

ACME deactivated-account requests with valid signatures/nonces return HTTP401
and `urn:ietf:params:acme:error:unauthorized`, including account resources and
issuance paths. Final transaction checks still reject a concurrent deactivation.
New/update contact validation reports `unsupportedContact` with the supported
`mailto` scheme, or `invalidContact` for malformed supported contacts, hfields
and multiple mailboxes; it does not echo caller-supplied contact values in errors.
These wire outcomes follow [RFC8555 sections7.3 and7.3.6](https://www.rfc-editor.org/rfc/rfc8555.html#section-7.3.6).
