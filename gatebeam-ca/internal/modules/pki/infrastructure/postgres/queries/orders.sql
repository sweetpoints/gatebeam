-- name: InsertOrder :exec
INSERT INTO pki_orders(id,account_id,directory,names,purpose,status,expires,challenges,revision) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9);
-- name: ReadOrder :one
SELECT * FROM pki_orders WHERE id=$1 AND account_id=$2 FOR UPDATE;
-- name: SaveOrder :execrows
UPDATE pki_orders SET status=$2,challenges=$3,revision=revision+1 WHERE id=$1 AND revision=$4;
-- name: ListOrders :many
SELECT id FROM pki_orders WHERE account_id=$1 AND id>$2 ORDER BY id LIMIT 100;
-- name: InsertCertificate :exec
INSERT INTO pki_certificates(order_id,issuer_id,serial,der,chain,not_before,not_after) VALUES($1,$2,$3,$4,$5,$6,$7);
-- name: ReadCertificate :one
SELECT * FROM pki_certificates WHERE order_id=$1;
