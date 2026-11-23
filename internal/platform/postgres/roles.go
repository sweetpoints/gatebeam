package postgres

import (
	"context"
	"gatebeam/db/roles"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MigrateRoles applies capability grants separately from schema migrations.
// Only the explicitly configured migration process may invoke it.
func MigrateRoles(ctx context.Context, p *pgxpool.Pool) error {
	return migrate(ctx, p, roles.Files, "gatebeam_role_version", 0x47415445524f4c45)
}
