-- +goose Up
-- Certificates owns all these aggregates and immutable material versions.
CREATE TABLE certificates_watermark(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),generation bigint NOT NULL DEFAULT 0);
INSERT INTO certificates_watermark(singleton) VALUES(true);
CREATE TABLE certificates_resources(kind text NOT NULL CHECK(kind IN ('spec','account','credential','trust')),id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),enabled boolean NOT NULL,PRIMARY KEY(kind,id));
CREATE TABLE certificates_revisions(kind text NOT NULL,id uuid NOT NULL,revision bigint NOT NULL CHECK(revision>0),body jsonb NOT NULL,pem bytea NOT NULL DEFAULT '',secret bytea NOT NULL DEFAULT '',PRIMARY KEY(kind,id,revision),FOREIGN KEY(kind,id) REFERENCES certificates_resources(kind,id));
CREATE TABLE certificates_versions(id uuid PRIMARY KEY,spec_id uuid NOT NULL,spec_revision bigint NOT NULL,body jsonb NOT NULL,certificate_pem bytea NOT NULL,encrypted_key bytea NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE certificates_attempts(spec_id uuid NOT NULL,spec_revision bigint NOT NULL,token text NOT NULL DEFAULT '',lease_until timestamptz NOT NULL DEFAULT '-infinity',failures integer NOT NULL DEFAULT 0,next_attempt timestamptz NOT NULL DEFAULT '-infinity',current_version uuid REFERENCES certificates_versions(id),PRIMARY KEY(spec_id,spec_revision));
-- +goose StatementBegin
CREATE FUNCTION certificates_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'immutable certificate material'; END; $$;
-- +goose StatementEnd
CREATE TRIGGER certificates_revision_immutable BEFORE UPDATE OR DELETE ON certificates_revisions FOR EACH ROW EXECUTE FUNCTION certificates_immutable();
CREATE TRIGGER certificates_version_immutable BEFORE UPDATE OR DELETE ON certificates_versions FOR EACH ROW EXECUTE FUNCTION certificates_immutable();
CREATE TABLE certificates_status(trust_id uuid NOT NULL,trust_revision bigint NOT NULL,generation text NOT NULL,profile_digest text NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(trust_id,trust_revision,generation));
CREATE TRIGGER certificates_status_immutable BEFORE UPDATE OR DELETE ON certificates_status FOR EACH ROW EXECUTE FUNCTION certificates_immutable();
CREATE TABLE certificates_challenges(owner text NOT NULL,binding text NOT NULL,body jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(owner,binding));
CREATE TABLE certificates_preparations(kind text NOT NULL,id uuid NOT NULL,revision bigint NOT NULL,token text NOT NULL DEFAULT '',lease_until timestamptz NOT NULL DEFAULT '-infinity',failures integer NOT NULL DEFAULT 0,next_attempt timestamptz NOT NULL DEFAULT '-infinity',PRIMARY KEY(kind,id,revision),FOREIGN KEY(kind,id,revision) REFERENCES certificates_revisions(kind,id,revision));
-- +goose Down
DROP TABLE certificates_preparations,certificates_challenges,certificates_status,certificates_attempts,certificates_versions,certificates_revisions,certificates_resources,certificates_watermark;
DROP FUNCTION certificates_immutable();
