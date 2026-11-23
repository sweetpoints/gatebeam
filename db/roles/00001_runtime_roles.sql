-- +goose Up
-- Capability roles are cluster objects; retain compatible identities and reject
-- pre-existing logins, authority/ownership or unrelated inherited privileges.
-- +goose StatementBegin
DO $capabilities$
DECLARE
  role_name text;
  existing record;
BEGIN
  FOREACH role_name IN ARRAY ARRAY[
    'gatebeam_pki_management',
    'gatebeam_pki_ca',
    'gatebeam_certificates_management',
    'gatebeam_certificates_worker',
    'gatebeam_certificates_edge',
    'gatebeam_observability_worker',
    'gatebeam_observability_reader',
    'gatebeam_observability_query_api',
    'gatebeam_notification_management',
    'gatebeam_notification_worker',
    'gatebeam_deployment_alert_writer',
    'gatebeam_backup_snapshot',
    'gatebeam_backup_worker',
    'gatebeam_backup_reader',
    'gatebeam_deployment_operations_reader',
    'gatebeam_deployment_operations_writer',
    'gatebeam_runtime_api',
    'gatebeam_runtime_worker',
    'gatebeam_runtime_edge',
    'gatebeam_runtime_ca'
  ] LOOP
    SELECT * INTO existing FROM pg_roles WHERE rolname=role_name;
    IF FOUND THEN
      IF existing.rolcanlogin OR existing.rolsuper OR existing.rolcreaterole
         OR existing.rolcreatedb OR existing.rolreplication OR existing.rolbypassrls
         OR EXISTS (SELECT 1 FROM pg_shdepend WHERE refclassid='pg_authid'::regclass
                    AND refobjid=existing.oid AND deptype='o')
         OR EXISTS (
           SELECT 1 FROM pg_auth_members m JOIN pg_roles parent ON parent.oid=m.roleid
           WHERE m.member=existing.oid AND (m.admin_option OR NOT (parent.rolname || '|' || role_name = ANY(ARRAY[
             'gatebeam_pki_management|gatebeam_runtime_api',
    'gatebeam_certificates_management|gatebeam_runtime_api',
    'gatebeam_observability_reader|gatebeam_runtime_api',
    'gatebeam_observability_query_api|gatebeam_runtime_api',
    'gatebeam_notification_management|gatebeam_runtime_api',
    'gatebeam_backup_reader|gatebeam_runtime_api',
    'gatebeam_deployment_operations_reader|gatebeam_runtime_api',
    'gatebeam_certificates_worker|gatebeam_runtime_worker',
    'gatebeam_observability_worker|gatebeam_runtime_worker',
    'gatebeam_notification_worker|gatebeam_runtime_worker',
    'gatebeam_deployment_alert_writer|gatebeam_runtime_worker',
    'gatebeam_backup_worker|gatebeam_runtime_worker',
    'gatebeam_certificates_edge|gatebeam_runtime_edge',
    'gatebeam_deployment_alert_writer|gatebeam_runtime_edge',
    'gatebeam_deployment_operations_writer|gatebeam_runtime_edge',
    'gatebeam_pki_ca|gatebeam_runtime_ca'
           ])))
         ) THEN
        RAISE EXCEPTION 'Conflicting capability role';
      END IF;
    ELSE
      EXECUTE format('CREATE ROLE %I NOLOGIN',role_name);
    END IF;
  END LOOP;
END
$capabilities$;
-- +goose StatementEnd

-- search_path. These are capability roles, never credentials or service logins.
-- Grant the appropriate role to separately provisioned API/CA logins. Runtime
-- logins must not own the schema/tables or inherit an owner/superuser role.


GRANT SELECT ON pki_issuers TO gatebeam_pki_management;
GRANT SELECT, INSERT ON pki_issuers TO gatebeam_pki_ca;
GRANT INSERT ON pki_serial_reservations TO gatebeam_pki_ca;
-- Both roles also need USAGE on the deployment schema; grant it using its actual
-- configured name. Neither role receives issuer mutation or private key access.

-- P2 authority split: API writes enrollment policy; CA can only bind accounts
-- to existing policy and consume EAB. Shared advisory principal locks require
-- no UPDATE privilege on principal rows.
GRANT SELECT,INSERT ON pki_principals,pki_grants TO gatebeam_pki_management;
GRANT UPDATE(disabled) ON pki_principals TO gatebeam_pki_management;
GRANT SELECT,INSERT ON pki_eab TO gatebeam_pki_management;
GRANT UPDATE(consumed) ON pki_eab TO gatebeam_pki_management;
GRANT SELECT ON pki_accounts TO gatebeam_pki_management;
GRANT SELECT ON pki_principals,pki_grants,pki_eab TO gatebeam_pki_ca;
GRANT UPDATE(consumed) ON pki_eab TO gatebeam_pki_ca;
GRANT SELECT,INSERT ON pki_accounts TO gatebeam_pki_ca;
GRANT UPDATE(thumbprint,public_key,status,contacts,revision) ON pki_accounts TO gatebeam_pki_ca;
GRANT SELECT,INSERT,DELETE ON pki_nonces TO gatebeam_pki_ca;

-- P3: only CA can append certificate DER and advance authorized orders.
GRANT SELECT,INSERT ON pki_orders,pki_certificates TO gatebeam_pki_ca;
GRANT UPDATE(status,challenges,revision) ON pki_orders TO gatebeam_pki_ca;
GRANT SELECT(order_id,issuer_id,serial,not_before,not_after) ON pki_certificates TO gatebeam_pki_management;

-- P4: immutable revocation authority is synchronously writable by API and CA.
GRANT SELECT,INSERT ON pki_revocations TO gatebeam_pki_management,gatebeam_pki_ca;
GRANT SELECT(id,account_id,names,purpose) ON pki_orders TO gatebeam_pki_management;
GRANT SELECT,INSERT ON pki_status_certificates,pki_crl_versions TO gatebeam_pki_ca;
GRANT UPDATE(number) ON pki_crl_versions TO gatebeam_pki_ca;

GRANT SELECT,INSERT ON pki_root_crl_state TO gatebeam_pki_ca;
GRANT UPDATE(number,der,revoked_serials) ON pki_root_crl_state TO gatebeam_pki_ca;

-- All issuer users read quarantine; none may erase it or admit an unsafe issuer.
GRANT SELECT ON pki_restore_quarantine TO gatebeam_pki_ca,gatebeam_pki_management;

-- Derived public status; issuer metadata refresh cannot alter DER or signing state.
GRANT UPDATE(key_fingerprint) ON pki_issuers TO gatebeam_pki_ca;


-- Run after migrations as schema owner. Grant these NOLOGIN capabilities to
-- separately provisioned service logins, plus USAGE on the configured schema.
-- They supplement existing identity/ingress/deployment/audit/jobs capabilities.
-- Runtime logins must never own the schema or inherit owner/superuser roles.



GRANT SELECT ON certificates_resources,certificates_revisions,certificates_versions,
 certificates_attempts,certificates_status,certificates_watermark
 TO gatebeam_certificates_management,gatebeam_certificates_worker;
GRANT INSERT ON certificates_resources,certificates_revisions TO gatebeam_certificates_management;
GRANT UPDATE(revision,enabled) ON certificates_resources TO gatebeam_certificates_management;
-- Management imports leaf keys; worker issues/renews them. Both only seal leaf
-- material to the edge's public recipient, never load its private identity.
GRANT INSERT ON certificates_versions,certificates_attempts
 TO gatebeam_certificates_management,gatebeam_certificates_worker;
GRANT UPDATE ON certificates_attempts,certificates_watermark
 TO gatebeam_certificates_management,gatebeam_certificates_worker;
GRANT SELECT,INSERT,UPDATE ON certificates_issuance_leases
 TO gatebeam_certificates_management,gatebeam_certificates_worker;
GRANT SELECT ON certificates_preparations TO gatebeam_certificates_management;
GRANT SELECT,INSERT,UPDATE ON certificates_preparations TO gatebeam_certificates_worker;
GRANT INSERT ON certificates_status TO gatebeam_certificates_worker;
GRANT SELECT,INSERT,UPDATE,DELETE ON certificates_challenges TO gatebeam_certificates_worker;
-- Edge cannot read provider ciphertext, claim issuance, or mutate material.
GRANT SELECT ON certificates_resources,certificates_versions,certificates_attempts,
 certificates_status,certificates_watermark TO gatebeam_certificates_edge;
GRANT SELECT(kind,id,revision,body,pem) ON certificates_revisions TO gatebeam_certificates_edge;
GRANT UPDATE ON certificates_watermark TO gatebeam_certificates_edge;
-- Remove obsolete broad role memberships from edge logins during upgrades.
-- Distinct age identities remain mandatory even if ciphertext is exposed.
-- No role here grants pki_* privileges or any CA signing capability.
-- Worker owns renewal and expiry event sequencing; API/edge cannot fabricate it.
GRANT SELECT,INSERT,UPDATE ON certificates_alert_outcomes TO gatebeam_certificates_worker;
GRANT INSERT ON outbox TO gatebeam_certificates_worker;


-- Run as migration owner; grant membership to the existing API/worker login roles.
-- These roles confer no certificate keys, issuer writes or cross-owner SQL.


GRANT SELECT,INSERT,UPDATE ON observability_segments TO gatebeam_observability_worker;
GRANT SELECT,INSERT,UPDATE ON observability_batches TO gatebeam_observability_worker;
GRANT SELECT,INSERT,UPDATE ON observability_stats TO gatebeam_observability_worker;
GRANT INSERT ON outbox TO gatebeam_observability_worker;
GRANT SELECT ON observability_stats TO gatebeam_observability_reader;
-- jobs enqueue privileges and identity/ingress current-authority read privileges
-- remain separately owned; these context roles do not widen them.

-- API owns durable Submit/Fetch metadata only. Its current identity/ingress
-- authorization grants are separate. It has no socket or object-store secrets.

GRANT SELECT ON observability_manifests,observability_archive_objects,observability_batches TO gatebeam_observability_query_api;
GRANT SELECT,INSERT,UPDATE,DELETE ON observability_queries TO gatebeam_observability_query_api;
GRANT SELECT,INSERT,UPDATE ON observability_manifests,observability_archive_objects TO gatebeam_observability_worker;
GRANT USAGE,SELECT ON SEQUENCE observability_manifests_sequence_seq TO gatebeam_observability_worker;
GRANT SELECT,INSERT,UPDATE,DELETE ON observability_queries TO gatebeam_observability_worker;
-- query-worker deliberately has NO database login, role or database mount.
-- Owner-ordered failure/recovery outcomes commit with their source writes.
GRANT SELECT,INSERT,UPDATE ON observability_alert_outcomes TO gatebeam_observability_worker;


-- Run as schema migration owner, then grant membership to existing service
-- logins and USAGE on the configured schema. These roles own no tables.



-- API can retain encrypted channel payloads but has only the public age sealer.
GRANT SELECT,INSERT,UPDATE ON notification_channels TO gatebeam_notification_management;
GRANT SELECT,INSERT ON notification_incidents,notification_transitions,notification_deliveries TO gatebeam_notification_management;
GRANT SELECT ON notification_attempts TO gatebeam_notification_management;
GRANT SELECT ON notification_channels TO gatebeam_notification_worker;
-- PostgreSQL row locks require UPDATE privilege on at least one column.
GRANT UPDATE(enabled) ON notification_channels TO gatebeam_notification_worker;
GRANT SELECT,INSERT,UPDATE ON notification_incidents,notification_transitions,notification_deliveries,notification_attempts TO gatebeam_notification_worker;
GRANT SELECT ON outbox TO gatebeam_notification_worker;
GRANT SELECT,INSERT ON consumer_receipts TO gatebeam_notification_worker;
GRANT SELECT,INSERT,UPDATE ON deployment_alert_outcomes TO gatebeam_deployment_alert_writer;
GRANT INSERT ON outbox TO gatebeam_deployment_alert_writer;
-- Platform audit/jobs and current identity/ingress authorization capabilities
-- are separately owned and must already be granted to API/worker service roles.
-- Do not grant notification worker CA, provider or leaf-key capabilities.


-- Dedicated export login receives this NOLOGIN capability only, no runtime
-- roles, object ownership, SECURITY DEFINER or server file/program privilege.


GRANT SELECT ON goose_db_version,jobs,job_attempts,audit,outbox,consumer_receipts,identity_watermark,identity_accounts,identity_challenges,identity_sessions,identity_recovery,identity_grants,identity_tokens,ingress_graph_watermark,ingress_groups,ingress_sites,ingress_site_groups,ingress_site_revisions,ingress_domains,ingress_targets,ingress_target_revisions,ingress_idempotency,deployment_candidates,deployment_releases,deployment_execution_reports,deployment_runtime,deployment_generation,deployment_target_runtime,pki_issuers,pki_serial_reservations,pki_principals,pki_grants,pki_eab,pki_accounts,pki_nonces,pki_orders,pki_certificates,pki_revocations,pki_crl_versions,pki_status_certificates,pki_root_crl_state,certificates_watermark,certificates_resources,certificates_revisions,certificates_versions,certificates_attempts,certificates_status,certificates_challenges,certificates_preparations,deployment_cloudflare,certificates_issuance_leases,deployment_route_verifications,observability_segments,observability_batches,observability_stats,observability_manifests,observability_archive_objects,observability_queries,notification_channels,notification_incidents,notification_transitions,notification_deliveries,notification_attempts,deployment_alert_outcomes,certificates_alert_outcomes,observability_alert_outcomes,backup_runs,identity_restore_bootstrap,pki_restore_quarantine TO gatebeam_backup_snapshot;
GRANT SELECT,INSERT,UPDATE,DELETE ON backup_runs TO gatebeam_backup_worker;

GRANT SELECT ON backup_runs TO gatebeam_backup_reader;
-- Local interactive bootstrap alone requires SELECT,UPDATE on
-- identity_restore_bootstrap; API/worker runtime logins must not arm it.


-- Run after migrations as owner. Grant membership to existing API/edge logins.


GRANT SELECT ON deployment_execution_reports,deployment_route_verifications,deployment_runtime TO gatebeam_deployment_operations_reader;
GRANT SELECT(kind,key,status,attempt) ON jobs TO gatebeam_deployment_operations_reader;
GRANT SELECT,INSERT,UPDATE ON deployment_execution_reports TO gatebeam_deployment_operations_writer;


-- Separate service LOGIN identities receive only one corresponding NOLOGIN role.
-- No runtime role owns a schema/table, creates objects, grants roles or migrates.





GRANT gatebeam_pki_management,gatebeam_certificates_management,
 gatebeam_observability_reader,gatebeam_observability_query_api,
 gatebeam_notification_management,gatebeam_backup_reader,
 gatebeam_deployment_operations_reader TO gatebeam_runtime_api;
GRANT gatebeam_certificates_worker,gatebeam_observability_worker,
 gatebeam_notification_worker,gatebeam_deployment_alert_writer,
 gatebeam_backup_worker TO gatebeam_runtime_worker;
GRANT gatebeam_certificates_edge,gatebeam_deployment_alert_writer,
 gatebeam_deployment_operations_writer TO gatebeam_runtime_edge;
GRANT gatebeam_pki_ca TO gatebeam_runtime_ca;

-- identity owner: API authentication and current read authorization in consumers.
-- Account/session rows contain encrypted seed/hash values, not decryption keys.
GRANT SELECT,INSERT,UPDATE,DELETE ON identity_accounts,identity_challenges,
 identity_sessions,identity_recovery,identity_grants,identity_tokens TO gatebeam_runtime_api;
GRANT SELECT,UPDATE ON identity_watermark TO gatebeam_runtime_api;
GRANT SELECT ON identity_accounts,identity_sessions,identity_grants,identity_tokens,
 identity_watermark TO gatebeam_runtime_edge,gatebeam_runtime_worker;
-- PostgreSQL FOR SHARE requires UPDATE on at least one column; this singleton
-- contains no grant or credential state and is constrained to its fixed value.
GRANT UPDATE(id) ON identity_watermark TO gatebeam_runtime_edge,gatebeam_runtime_worker;

-- ingress owner: API drafts; edge alone finalizes selected published heads.
GRANT SELECT,INSERT,UPDATE,DELETE ON ingress_groups,ingress_sites,
 ingress_site_groups,ingress_site_revisions,ingress_domains,ingress_targets,
 ingress_target_revisions,ingress_idempotency TO gatebeam_runtime_api;
GRANT SELECT,UPDATE ON ingress_graph_watermark TO gatebeam_runtime_api;
GRANT SELECT ON ingress_groups,ingress_sites,ingress_site_groups,
 ingress_site_revisions,ingress_domains,ingress_targets,ingress_target_revisions,
 ingress_graph_watermark TO gatebeam_runtime_edge,gatebeam_runtime_worker;
GRANT UPDATE(id) ON ingress_graph_watermark TO gatebeam_runtime_edge,gatebeam_runtime_worker;
GRANT UPDATE(published_revision) ON ingress_sites,ingress_targets TO gatebeam_runtime_edge;
GRANT INSERT,DELETE ON ingress_domains TO gatebeam_runtime_edge;

-- deployment owner: API prepares/queues; edge validates/finalizes; worker only
-- derives runtime inputs and marks the bounded dirty queue.
GRANT SELECT,INSERT ON deployment_candidates,deployment_releases TO gatebeam_runtime_api;
GRANT UPDATE(id) ON deployment_candidates TO gatebeam_runtime_api,gatebeam_runtime_edge;
GRANT SELECT ON deployment_candidates,deployment_releases,deployment_runtime,
 deployment_generation,deployment_target_runtime,deployment_cloudflare TO gatebeam_runtime_api,gatebeam_runtime_worker,gatebeam_runtime_edge;
GRANT UPDATE ON deployment_releases TO gatebeam_runtime_edge;
GRANT INSERT,UPDATE ON deployment_runtime TO gatebeam_runtime_edge;
GRANT SELECT,INSERT ON deployment_route_verifications TO gatebeam_runtime_edge;
GRANT INSERT,UPDATE ON deployment_target_runtime TO gatebeam_runtime_worker,gatebeam_runtime_edge;
GRANT UPDATE ON deployment_generation TO gatebeam_runtime_worker,gatebeam_runtime_edge;
GRANT INSERT,UPDATE ON deployment_cloudflare TO gatebeam_runtime_worker;

-- Shared platform queue is NOT per-kind database isolation: assembly ClaimKinds,
-- current credentials, immutable artifact and lease fences remain mandatory.
GRANT SELECT,INSERT,UPDATE ON jobs,job_attempts TO gatebeam_runtime_worker,gatebeam_runtime_edge;
GRANT SELECT,INSERT ON jobs TO gatebeam_runtime_api;
GRANT INSERT ON audit TO gatebeam_runtime_api,gatebeam_runtime_worker,gatebeam_runtime_edge,gatebeam_runtime_ca;
GRANT SELECT(id,action,actor_id,occurred_at) ON audit TO gatebeam_runtime_api;
GRANT INSERT ON outbox TO gatebeam_runtime_api,gatebeam_runtime_ca;
-- Query worker has no database role or network. Backup exporter receives only
-- gatebeam_backup_snapshot, never these runtime roles or their private keys.

-- Only the PKI-owned public projection is needed for material fences.
GRANT SELECT ON pki_leaf_status TO gatebeam_runtime_api,gatebeam_runtime_edge,gatebeam_runtime_worker;
-- +goose Down
-- Removing shared capability roles or grants can break still-running versions.
-- This migration is intentionally forward-only.
-- +goose StatementBegin
DO $forward_only$ BEGIN RAISE EXCEPTION 'Capability migrations are forward-only'; END $forward_only$;
-- +goose StatementEnd
