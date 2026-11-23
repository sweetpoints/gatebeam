package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/modules/backup/domain"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

type Catalog struct{ DB *pgxpool.Pool }

func (c Catalog) Confirm(ctx context.Context, a application.Artifact) error {
	b, e := json.Marshal(a.Manifest)
	if e != nil {
		return e
	}
	tag, e := c.DB.Exec(ctx, `INSERT INTO backup_runs VALUES($1,$2,$3,$4,$5) ON CONFLICT(id) DO UPDATE SET id=EXCLUDED.id WHERE backup_runs.cipher_sha256=EXCLUDED.cipher_sha256 AND backup_runs.bytes=EXCLUDED.bytes AND backup_runs.manifest=EXCLUDED.manifest`, a.Manifest.ID, a.Manifest.Created, b, a.SHA256, a.Bytes)
	if e != nil || tag.RowsAffected() != 1 {
		return domain.ErrInvalid
	}
	return nil
}
func (c Catalog) Expired(ctx context.Context, before time.Time, keep string) ([]string, error) {
	rows, e := c.DB.Query(ctx, `SELECT id FROM backup_runs WHERE created_at<$1 AND id<>$2 ORDER BY created_at LIMIT 100`, before, keep)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if e = rows.Scan(&id); e != nil {
			return nil, e
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
func (c Catalog) Forget(ctx context.Context, id string) error {
	_, e := c.DB.Exec(ctx, `DELETE FROM backup_runs WHERE id=$1`, id)
	return e
}
