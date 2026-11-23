-- name: Enqueue :one
INSERT INTO jobs(kind,key,payload) VALUES($1,$2,$3) ON CONFLICT(kind,key) DO UPDATE SET key=EXCLUDED.key RETURNING id;
-- name: Exhaust :exec
WITH exhausted AS (
 SELECT id FROM jobs WHERE target_node_id IS NULL AND status='running' AND deadline<=clock_timestamp() AND attempt>=max_attempts
 ORDER BY deadline,id FOR UPDATE SKIP LOCKED LIMIT 32
)
UPDATE jobs SET status='failed',lease_token=NULL FROM exhausted WHERE jobs.id=exhausted.id;
-- name: Claim :one
WITH candidate AS (
 SELECT id FROM jobs WHERE target_node_id IS NULL AND (status='pending' OR (status='running' AND deadline<=clock_timestamp())) AND attempt<max_attempts ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE jobs SET status='running', worker=$1, lease_token=gen_random_uuid()::text, deadline=clock_timestamp()+make_interval(secs => sqlc.arg(lease_seconds)::double precision), attempt=attempt+1
FROM candidate WHERE jobs.id=candidate.id RETURNING jobs.id,jobs.kind,jobs.payload,jobs.lease_token,jobs.deadline,jobs.attempt;
-- name: RecordAttempt :exec
INSERT INTO job_attempts(job_id,attempt,lease_token,worker) VALUES($1,$2,$3,$4);
-- name: Complete :execrows
UPDATE jobs SET status='completed' WHERE id=$1 AND lease_token=$2 AND status='running' AND deadline>clock_timestamp();
-- name: CompleteAttempt :exec
UPDATE job_attempts SET completed_at=clock_timestamp() WHERE job_id=$1 AND lease_token=$2;

-- name: ClaimKinds :one
WITH candidate AS (
 SELECT id FROM jobs WHERE target_node_id IS NULL AND kind=ANY(sqlc.arg(kinds)::text[]) AND (status='pending' OR (status='running' AND deadline<=clock_timestamp())) AND attempt<max_attempts ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE jobs SET status='running', worker=$1, lease_token=gen_random_uuid()::text, deadline=clock_timestamp()+make_interval(secs => sqlc.arg(lease_seconds)::double precision), attempt=attempt+1
FROM candidate WHERE jobs.id=candidate.id RETURNING jobs.id,jobs.kind,jobs.payload,jobs.lease_token,jobs.deadline,jobs.attempt;

-- name: ExhaustKinds :exec
WITH exhausted AS (
 SELECT id FROM jobs WHERE target_node_id IS NULL AND kind=ANY(sqlc.arg(kinds)::text[]) AND status='running' AND deadline<=clock_timestamp() AND attempt>=max_attempts
 ORDER BY deadline,id FOR UPDATE SKIP LOCKED LIMIT 32
)
UPDATE jobs SET status='failed',lease_token=NULL FROM exhausted WHERE jobs.id=exhausted.id;
-- name: Fence :one
SELECT id FROM jobs WHERE id=$1 AND lease_token=$2 AND status='running' AND deadline>clock_timestamp() FOR UPDATE;

-- name: EnqueueTarget :one
INSERT INTO jobs(kind,key,payload,target_node_id,target_node_epoch) VALUES($1,$2,$3,$4,$5)
ON CONFLICT(kind,key) DO UPDATE SET key=EXCLUDED.key
WHERE jobs.target_node_id=EXCLUDED.target_node_id AND jobs.target_node_epoch=EXCLUDED.target_node_epoch AND jobs.payload=EXCLUDED.payload
RETURNING id;

-- name: ClaimTargetKinds :one
WITH candidate AS (
 SELECT id FROM jobs WHERE target_node_id=sqlc.arg(node_id)::uuid AND target_node_epoch=sqlc.arg(node_epoch)::bigint AND kind=ANY(sqlc.arg(kinds)::text[])
 AND (status='pending' OR (status='running' AND deadline<=clock_timestamp())) AND attempt<max_attempts
 ORDER BY created_at,id FOR UPDATE SKIP LOCKED LIMIT 1
)
UPDATE jobs SET status='running',worker=sqlc.arg(worker)::text,lease_token=gen_random_uuid()::text,
 deadline=clock_timestamp()+make_interval(secs=>sqlc.arg(lease_seconds)::double precision),attempt=attempt+1
FROM candidate WHERE jobs.id=candidate.id
RETURNING jobs.id,jobs.kind,jobs.payload,jobs.lease_token,jobs.deadline,jobs.attempt,jobs.target_node_id,jobs.target_node_epoch;

-- name: ExhaustTargetKinds :exec
WITH exhausted AS (
 SELECT id FROM jobs WHERE target_node_id=sqlc.arg(node_id)::uuid AND target_node_epoch=sqlc.arg(node_epoch)::bigint AND kind=ANY(sqlc.arg(kinds)::text[])
 AND status='running' AND deadline<=clock_timestamp() AND attempt>=max_attempts ORDER BY deadline,id FOR UPDATE SKIP LOCKED LIMIT 32
)
UPDATE jobs SET status='failed',lease_token=NULL FROM exhausted WHERE jobs.id=exhausted.id;

-- name: Renew :execrows
UPDATE jobs SET deadline=clock_timestamp()+make_interval(secs=>sqlc.arg(lease_seconds)::double precision)
WHERE id=$1 AND lease_token=$2 AND status='running' AND deadline>clock_timestamp();

-- name: Release :execrows
UPDATE jobs SET status='pending',lease_token=NULL,deadline=NULL,worker=NULL
WHERE id=$1 AND lease_token=$2 AND status='running' AND deadline>clock_timestamp();
