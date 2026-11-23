-- name: ReadLock :exec
SELECT id FROM ingress_graph_watermark WHERE id=true FOR SHARE;
-- name: WriteLock :exec
SELECT id FROM ingress_graph_watermark WHERE id=true FOR UPDATE;
-- name: Sites :many
SELECT s.id::text,s.deleted,s.name,s.draft_revision,coalesce(s.published_revision,0)::bigint AS published_revision,d.config,p.config AS published,ARRAY(SELECT g.group_id::text FROM ingress_site_groups g WHERE g.site_id=s.id ORDER BY g.group_id)::text[] AS groups
FROM ingress_sites s JOIN ingress_site_revisions d ON d.site_id=s.id AND d.revision=s.draft_revision LEFT JOIN ingress_site_revisions p ON p.site_id=s.id AND p.revision=s.published_revision ORDER BY s.id;
-- name: Targets :many
SELECT t.id::text,t.draft_revision,coalesce(t.published_revision,0)::bigint AS published_revision,d.config,p.config AS published FROM ingress_targets t JOIN ingress_target_revisions d ON d.target_id=t.id AND d.revision=t.draft_revision LEFT JOIN ingress_target_revisions p ON p.target_id=t.id AND p.revision=t.published_revision ORDER BY t.id;
-- name: Groups :many
SELECT id::text,name,revision FROM ingress_groups ORDER BY id;
-- name: SiteGroups :one
SELECT ARRAY(SELECT g.group_id::text FROM ingress_site_groups g WHERE g.site_id=s.id ORDER BY g.group_id)::text[] AS groups
FROM ingress_sites s JOIN ingress_site_revisions d ON d.site_id=s.id AND d.revision=s.draft_revision WHERE s.id=sqlc.arg(id)::uuid;
-- name: CreateSite :exec
INSERT INTO ingress_sites(id,name,draft_revision) VALUES(sqlc.arg(id)::uuid,sqlc.arg(name),1);
-- name: AppendSiteRevision :exec
INSERT INTO ingress_site_revisions(site_id,revision,config) VALUES(sqlc.arg(id)::uuid,sqlc.arg(revision),sqlc.arg(config));
-- name: UpdateSite :execrows
UPDATE ingress_sites SET draft_revision=sqlc.arg(revision) WHERE id=sqlc.arg(id)::uuid AND draft_revision=sqlc.arg(expected) AND NOT deleted;
-- name: ClearGroups :exec
DELETE FROM ingress_site_groups WHERE site_id=sqlc.arg(id)::uuid;
-- name: AddGroup :exec
INSERT INTO ingress_site_groups(site_id,group_id) VALUES(sqlc.arg(site_id)::uuid,sqlc.arg(group_id)::uuid);
-- name: ClearDomains :exec
DELETE FROM ingress_domains WHERE site_id=sqlc.arg(id)::uuid;
-- name: ClaimDomain :exec
INSERT INTO ingress_domains(site_id,domain) VALUES(sqlc.arg(id)::uuid,sqlc.arg(domain));
-- name: DeleteSite :execrows
UPDATE ingress_sites SET deleted=true WHERE id=sqlc.arg(id)::uuid AND draft_revision=sqlc.arg(expected) AND published_revision IS NULL AND NOT deleted;
-- name: SaveGroup :execrows
INSERT INTO ingress_groups(id,name,revision) SELECT sqlc.arg(id)::uuid,sqlc.arg(name),1 WHERE sqlc.arg(expected)::bigint=0 ON CONFLICT(id) DO UPDATE SET name=excluded.name,revision=ingress_groups.revision+1 WHERE ingress_groups.revision=sqlc.arg(expected);
-- name: UpdateGroup :execrows
UPDATE ingress_groups SET name=sqlc.arg(name),revision=revision+1 WHERE id=sqlc.arg(id)::uuid AND revision=sqlc.arg(expected);
-- name: DeleteGroup :execrows
DELETE FROM ingress_groups WHERE id=sqlc.arg(id)::uuid AND revision=sqlc.arg(expected);
-- name: CreateTarget :exec
INSERT INTO ingress_targets(id,draft_revision) VALUES(sqlc.arg(id)::uuid,1);
-- name: AppendTargetRevision :exec
INSERT INTO ingress_target_revisions(target_id,revision,config) VALUES(sqlc.arg(id)::uuid,sqlc.arg(revision),sqlc.arg(config));
-- name: UpdateTarget :execrows
UPDATE ingress_targets SET draft_revision=sqlc.arg(revision) WHERE id=sqlc.arg(id)::uuid AND draft_revision=sqlc.arg(expected);
-- name: DeleteTarget :execrows
DELETE FROM ingress_targets WHERE id=sqlc.arg(id)::uuid AND draft_revision=sqlc.arg(expected);

-- name: Receipt :one
SELECT command_digest,result FROM ingress_idempotency WHERE actor_id=sqlc.arg(actor_id) AND credential_id=sqlc.arg(credential_id) AND credential_kind=sqlc.arg(credential_kind) AND method=sqlc.arg(method) AND resource_path=sqlc.arg(resource_path) AND idempotency_key=sqlc.arg(idempotency_key) AND expires>now();
-- name: SaveReceipt :execrows
INSERT INTO ingress_idempotency(actor_id,credential_id,credential_kind,method,resource_path,idempotency_key,command_digest,result) VALUES(sqlc.arg(actor_id),sqlc.arg(credential_id),sqlc.arg(credential_kind),sqlc.arg(method),sqlc.arg(resource_path),sqlc.arg(idempotency_key),sqlc.arg(command_digest),sqlc.arg(result)) ON CONFLICT(actor_id,credential_id,credential_kind,method,resource_path,idempotency_key) DO UPDATE SET command_digest=excluded.command_digest,result=excluded.result,expires=excluded.expires WHERE ingress_idempotency.expires<=now();

-- name: PublishSite :execrows
UPDATE ingress_sites s SET published_revision=sqlc.arg(revision) WHERE s.id=sqlc.arg(id)::uuid AND NOT s.deleted AND EXISTS(SELECT 1 FROM ingress_site_revisions r WHERE r.site_id=s.id AND r.revision=sqlc.arg(revision) AND r.config=sqlc.arg(config)::jsonb);
-- name: PublishTarget :execrows
UPDATE ingress_targets t SET published_revision=sqlc.arg(revision) WHERE t.id=sqlc.arg(id)::uuid AND EXISTS(SELECT 1 FROM ingress_target_revisions r WHERE r.target_id=t.id AND r.revision=sqlc.arg(revision) AND r.config=sqlc.arg(config)::jsonb);
