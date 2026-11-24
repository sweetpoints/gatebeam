# Gatebeam CA

A Go service for private X.509 certificates in the root Gatebeam Go workspace. Run the build and test examples below from this module directory. It serves independent
serverAuth and clientAuth ACME v2 directories with External Account Binding
(EAB) and HTTP-01. Relying parties read OCSP and CRLs over a separate internal
HTTP listener. Source derived from the PKI module at Gatebeam revision
`95c38401b43005fbad14fcda924ac79dbae739e7`.

- [ACME v2 and EAB (RFC 8555)](https://www.rfc-editor.org/rfc/rfc8555)
- [X.509 certificate and CRL profile (RFC 5280)](https://www.rfc-editor.org/rfc/rfc5280)
- [OCSP (RFC 6960)](https://www.rfc-editor.org/rfc/rfc6960)

## Build and provision

Build with Go 1.27 or later and provision a dedicated PostgreSQL 18 database.
Run schema and role migrations as the schema owner with permission to create
the two capability roles. The DSN file contains one PostgreSQL connection
string and is readable only by the migration operator. Use the same schema in
`search_path` for each database login.

```sh
go build -o bin/gatebeam-ca ./cmd/gatebeam-ca
bin/gatebeam-ca migrate -database-file /secure/ca-owner.dsn
bin/gatebeam-ca migrate-roles -database-file /secure/ca-owner.dsn
```

Create a login for the serving process and a separate login for each CA
operator. Grant `gatebeam_ca_runtime` to the serving login and
`gatebeam_ca_admin` to the operator logins. Use restricted logins with the
default inherited role membership, no ownership, and no database or role
creation privileges. Audit rows record the authenticated database login
for enrollment, EAB issuance, principal disabling and administrator revocation.

## Prepare issuer and start

Run the ceremony on the offline machine with two new absolute output paths
whose parent directories exist:

```sh
gatebeam-ca bootstrap \
  -offline /offline/root-v1 -online /transfer/online-v1 \
  -root-name 'Private Root' -issuer-name 'Private Issuer' \
  -status-origin http://ca.internal.example:8081
```

Keep the root private key offline. Transfer only the online directory to the
serving host. The online directory contains the issuer and delegated root OCSP
signing material, the age identity, and the initially signed root CRL. Use
`gatebeam-ca import -h` for offline import of pre-provisioned issuer material.

Provision a TLS server certificate and key for the hostname in `origin` before
starting the ACME listener. The certificate may chain to a separate trust root
configured with `tls_trust_file`. If omitted, the CA uses `root_file` to verify
its HTTPS identity. Distribute that HTTPS trust anchor to ACME clients and
distribute the leaf-issuing trust root to mTLS peers. Use the documented PEM
paths and protect private files with OS permissions. The service re-reads its
TLS identity from disk when clients connect. The operator must provision and
renew this transport identity and publish fresh, offline-signed root CRLs.
Keep the public status origin stable so URLs in issued certificates remain valid.

Adapt [the serving configuration](examples/serve.json) to your private IPs,
DNS, and exact certificate names. Allow the CA to reach HTTP-01 responders
on TCP 80 within the explicitly configured validation networks. Block any
management or metadata networks in the deny list. Start the service:

```sh
gatebeam-ca serve -config /etc/gatebeam-ca/serve.json
```

Provision a dedicated service account and use the
[systemd service example](../deploy/pki/gatebeam-ca.service.example) on the CA
host. Install the prebuilt CA binary or run the separately published
`gatebeam-ca` image with the same configuration and CA-owned database.
Grant the gateway only network access to the private protocol listeners.

## Enroll and revoke

Set up [the administrator configuration](examples/admin.json) with the public
recipient from `recipient.txt`, the same exact-name policies, and the
operator's own PostgreSQL DSN file. Run these commands in a trusted
administration environment with access to that role.

```sh
gatebeam-ca authorize -config admin.json -directory server \
  -names backend.internal.example -expires "$GRANT_EXPIRY_RFC3339"
gatebeam-ca issue-eab -config admin.json -grant "$GRANT_ID" -output ./eab.json
gatebeam-ca inspect -config admin.json
gatebeam-ca revoke -config admin.json -issuer "$ISSUER_ID" -serial "$SERIAL" -reason 1
```

Set the grant expiry to a future RFC 3339 timestamp that covers the intended
issuance and renewal period. EAB is one-time and valid for up to 15 minutes.
Load the returned KID and base64url HMAC with the ACME client's EAB options and
retain its account key for automatic renewal under the enrollment. Use
`/acme/server/directory` or `/acme/client/directory` under `origin`, matching the
grant. `disable` denies further use by a principal. Revoke existing leaf
certificates separately to publish their status through OCSP and CRLs.

## Verification

```sh
go test ./...
go vet ./...
GATEBEAM_CA_TEST_DATABASE_URL="$DISPOSABLE_POSTGRES_URL" \
  GATEBEAM_TEST_OPENSSL="$(command -v openssl)" \
  go test -tags integration ./... -count=1
```

Use a disposable PostgreSQL instance with a test login allowed to create
schemas and roles. The integration suite exercises standalone listeners with
restricted logins, Lego EAB registration, X.509 signing, and OCSP/CRL checks.
