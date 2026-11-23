# Gradual public-to-private migration

Keep the existing public entrance working while introducing Gatebeam as a
separate entrance. No step here changes DNS automatically, installs a business
agent, or authorizes live production writes. The operator chooses the migration
window, traffic cohort, reversible DNS/routing action and rollback thresholds.

1. Inventory exact domains, route prefixes, methods, body/time limits, WebSocket
   and streaming behavior, default/upstream Host, SNI, certificate chains and
   access policy. Record old entrance IPs and current DNS TTL. Establish a
   read-only GET verification path for every affected route; avoid probes with
   application side effects.
2. Provision the gateway using the deployment runbook. Keep API/DB/CA management
   addresses outside business target allowlists. Obtain management TLS first,
   then site certificates through standard import or ACME. For HTTP-01, route
   the public challenge to the new edge's shared webroot before first site
   publication; if this cannot be done without disturbing the old entrance,
   choose DNS-01 with explicit scoped credentials and real propagation checks.
3. For private origins, use distinct A/B names and certificate/client state.
   Obtain standard serverAuth and clientAuth credentials from the separate
   ACME directories with EAB; bootstrap transport trust out of band. Keep the
   offline root and intermediate signing keys off business servers. Configure
   standard Nginx full-chain OCSP or current CRLs according to the chosen policy.
4. Configure the target group, health/DNS policy and site draft. Preserve the
   intended business Host independently from the TLS verification name. Normal
   mode sends the configured SNI. `verify_only` is for a dedicated listener that
   sends no SNI while still checking the exact certificate name, chain, time,
   CRL and clientAuth. Prove its default certificate is correct and every Host
   vhost enforces the same mTLS/OCSP policy; unknown Host must be rejected.
   Nginx 421 for mismatched SNI/Host is a refusal, not proof of successful
   independent SNI routing. Never disable verification to pass this check.
5. Publish explicitly with current credentials and review the immutable diff.
   Wait for the completed DB receipt and exact native TLS/private-version/artifact
   match. Review each affected domain/SNI/read-only route result. The global
   post-apply probe budget is five seconds at concurrency eight; exhaustion
   fails/restores the candidate, never truncates the plan and calls it verified.
   A maintenance/disabled or missing authorized CF/AOP/mTLS probe identity is an
   explicit policy outcome, not an observed successful business request.
6. Run preflight for both `role=old` and `role=new`, with the actual declared
   `mode=direct` or `mode=cloudflare`, domain and selected IP:TLS port. Check
   both entrances before changing DNS. Preserve Host/SNI and standard trust.
   Direct success does not establish Cloudflare/AOP success; absent provider
   authority or probe identity must remain an unresolved production gate.
7. Exercise owned/staging faults: stop one origin, change an owned DNS answer,
   expire/revoke an old publisher session, and verify periodic worker changes
   only runtime generation of the last verified logical configuration. Retain
   an unrelated draft and prove it is untouched. Verify old lease/cancelled jobs
   cannot finalize. During API/DB outage verify existing traffic and per-site
   CF expiry behavior with fresh connections.
8. In a separately approved production window, change only the chosen cohort's
   DNS/routing. Observe both entrances throughout TTL convergence, new TLS
   connections, route errors/latency, health, authentication and revocation.
   Do not remove the old entrance until the operator's observation window and
   rollback conditions are satisfied. Revert that explicit DNS/routing action
   if needed; keep the old entrance reachable until caches and long-lived
   connections have drained.

Revocation assertions require a fresh upstream TLS handshake. Existing pooled
TLS, WebSocket or resumed sessions can retain earlier authentication; use the
standard deployment's explicit session-resumption policy and new connections
when testing. Disabling an enrollment principal prevents issuance but does not
revoke existing leaves or terminate connections. Unknown OCSP is not CRL revoked:
a valid unknown post-backup leaf may pass a stale CRL. An unproved restore stays
quarantined until offline issuer-wide revocation/trust rotation or proven latest
state; do not reopen CRL-only traffic simply because one known old leaf fails.

Record source/artifacts, exact old/new endpoints, route results and expected
policy refusals, current security bindings, DNS action, observation window and
rollback decision in a private per-run record using the acceptance template.
Local fixtures establish mechanisms and bounded capacity; real Cloudflare/R2,
public CA, operator DNS and business application acceptance are distinct gates.
