-- +goose Up
-- ingress owns its aggregates and immutable revision bodies. Identity is referenced only through application ports.
CREATE TABLE ingress_graph_watermark(id boolean PRIMARY KEY DEFAULT true CHECK(id));
INSERT INTO ingress_graph_watermark VALUES(true);
CREATE TABLE ingress_groups(id uuid PRIMARY KEY,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),revision bigint NOT NULL CHECK(revision>0));
CREATE TABLE ingress_sites(id uuid PRIMARY KEY,deleted boolean NOT NULL DEFAULT false,name text NOT NULL CHECK(length(name) BETWEEN 1 AND 128),draft_revision bigint NOT NULL CHECK(draft_revision>0),published_revision bigint CHECK(published_revision>0));
CREATE TABLE ingress_site_groups(site_id uuid NOT NULL REFERENCES ingress_sites(id) ON DELETE CASCADE,group_id uuid NOT NULL REFERENCES ingress_groups(id) ON DELETE CASCADE,PRIMARY KEY(site_id,group_id));
CREATE TABLE ingress_site_revisions(site_id uuid NOT NULL REFERENCES ingress_sites(id) ON DELETE CASCADE,revision bigint NOT NULL CHECK(revision>0),config jsonb NOT NULL,PRIMARY KEY(site_id,revision));
ALTER TABLE ingress_sites ADD CONSTRAINT ingress_draft_head FOREIGN KEY(id,draft_revision) REFERENCES ingress_site_revisions(site_id,revision) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ingress_sites ADD CONSTRAINT ingress_published_head FOREIGN KEY(id,published_revision) REFERENCES ingress_site_revisions(site_id,revision) DEFERRABLE INITIALLY DEFERRED;
CREATE TABLE ingress_domains(domain text PRIMARY KEY CHECK(domain=lower(domain)),site_id uuid NOT NULL REFERENCES ingress_sites(id) ON DELETE CASCADE);
CREATE TABLE ingress_targets(id uuid PRIMARY KEY,draft_revision bigint NOT NULL CHECK(draft_revision>0),published_revision bigint CHECK(published_revision>0));
CREATE TABLE ingress_target_revisions(target_id uuid NOT NULL REFERENCES ingress_targets(id) ON DELETE CASCADE,revision bigint NOT NULL CHECK(revision>0),config jsonb NOT NULL,PRIMARY KEY(target_id,revision));
ALTER TABLE ingress_targets ADD CONSTRAINT ingress_target_draft_head FOREIGN KEY(id,draft_revision) REFERENCES ingress_target_revisions(target_id,revision) DEFERRABLE INITIALLY DEFERRED;
ALTER TABLE ingress_targets ADD CONSTRAINT ingress_target_published_head FOREIGN KEY(id,published_revision) REFERENCES ingress_target_revisions(target_id,revision) DEFERRABLE INITIALLY DEFERRED;
-- No secrets are stored: only command digests and resource/revision receipts.
CREATE TABLE ingress_idempotency(actor_id text NOT NULL,credential_id text NOT NULL,credential_kind text NOT NULL,method text NOT NULL,resource_path text NOT NULL,idempotency_key text NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 128),command_digest text NOT NULL,result jsonb NOT NULL,expires timestamptz NOT NULL DEFAULT now()+interval '24 hours',PRIMARY KEY(actor_id,credential_id,credential_kind,method,resource_path,idempotency_key));
CREATE INDEX ingress_idempotency_expiry ON ingress_idempotency(expires);
-- +goose Down
DROP TABLE ingress_idempotency;
ALTER TABLE ingress_targets DROP CONSTRAINT ingress_target_draft_head,DROP CONSTRAINT ingress_target_published_head;
DROP TABLE ingress_target_revisions,ingress_targets;
ALTER TABLE ingress_sites DROP CONSTRAINT ingress_draft_head,DROP CONSTRAINT ingress_published_head;
DROP TABLE ingress_domains,ingress_site_revisions,ingress_site_groups,ingress_sites,ingress_groups,ingress_graph_watermark;
