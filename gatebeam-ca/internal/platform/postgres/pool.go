package postgres

import (
	"context"
	"errors"
	"gatebeam-ca/db/migrations"
	"gatebeam-ca/db/roles"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

var ErrUnavailable = errors.New("database unavailable")

func Open(ctx context.Context, databaseFile string) (*pgxpool.Pool, error) {
	f, e := os.Open(databaseFile)
	if e != nil {
		return nil, errors.New("database secret unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() {
		return nil, errors.New("database secret unavailable")
	}
	data, e := io.ReadAll(io.LimitReader(f, 65537))
	if e != nil || len(data) == 0 || len(data) > 65536 {
		return nil, errors.New("database secret unavailable")
	}
	pc, e := pgxpool.ParseConfig(strings.TrimSpace(string(data)))
	if e != nil {
		return nil, errors.New("invalid database configuration")
	}
	pc.MaxConns = 8
	pc.MinConns = 0
	pc.ConnConfig.ConnectTimeout = 5 * time.Second
	p, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		return nil, ErrUnavailable
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if e = p.Ping(c); e != nil {
		p.Close()
		return nil, ErrUnavailable
	}
	return p, nil
}
func Migrate(ctx context.Context, p *pgxpool.Pool) error {
	return migrate(ctx, p, migrations.Files, "goose_db_version", 0x4742434144420001)
}

func MigrateRoles(ctx context.Context, p *pgxpool.Pool) error {
	return migrate(ctx, p, roles.Files, "goose_ca_roles_version", 0x4742434144420002)
}

func migrate(ctx context.Context, p *pgxpool.Pool, files fs.FS, table string, lockID int64) error {
	db := stdlib.OpenDBFromPool(p)
	defer db.Close()
	locker, e := lock.NewPostgresSessionLocker(lock.WithLockID(lockID), lock.WithLockTimeout(1, 30), lock.WithUnlockTimeout(1, 5))
	if e != nil {
		return errors.New("migration lock unavailable")
	}
	provider, e := goose.NewProvider(goose.DialectPostgres, db, files, goose.WithDisableGlobalRegistry(true), goose.WithTableName(table), goose.WithSessionLocker(locker))
	if e != nil {
		return errors.New("migration initialization failed")
	}
	if _, e = provider.Up(ctx); e != nil {
		return errors.New("migration failed")
	}
	return nil
}
