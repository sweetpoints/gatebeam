package recovery

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"gatebeam/internal/modules/backup/application"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	platform "gatebeam/internal/platform/postgres"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Destination struct {
	Admin               *pgxpool.Pool
	Directory, Identity string
	Database, Output    string
}

func (d *Destination) Stage(ctx context.Context, a application.Archive) error {
	if d.Database != "" || validate(a) != nil {
		return ErrRecovery
	}
	var e error
	a, e = normalizeArchive(a)
	if e != nil {
		return e
	}
	keys, e := archive.OpenCapsulesForCA(a.Files, a.Manifest.Epoch, d.Identity, a.Manifest.ExternalCA)
	if e != nil {
		return e
	}
	cfg := d.Admin.Config().Copy()
	host := cfg.ConnConfig.Host
	addr, e := netip.ParseAddr(host)
	if !strings.HasPrefix(host, "/") && (e != nil || !addr.IsLoopback()) {
		return ErrRecovery
	}
	if len(cfg.ConnConfig.Fallbacks) > 0 {
		return ErrRecovery
	}
	st, e := os.Lstat(d.Directory)
	if e != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return ErrRecovery
	}
	var nonce [12]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ErrRecovery
	}
	name := "gatebeam_restore_" + hex.EncodeToString(nonce[:])
	quoted := pgx.Identifier{name}.Sanitize()
	// A new database is always generated locally. No source-controlled name,
	// credentials, roles, grants, commands, connection strings or DDL are restored.
	if _, e = d.Admin.Exec(ctx, `CREATE DATABASE `+quoted+` TEMPLATE template0 CONNECTION LIMIT 0`); e != nil {
		return ErrRecovery
	}
	ok := false
	defer func() {
		if !ok {
			c, done := context.WithTimeout(context.Background(), 5*time.Second)
			defer done()
			d.Admin.Exec(c, `DROP DATABASE `+quoted+` WITH (FORCE)`)
		}
	}()
	if _, e = d.Admin.Exec(ctx, `REVOKE CONNECT ON DATABASE `+quoted+` FROM PUBLIC`); e != nil {
		return ErrRecovery
	}
	cfg.ConnConfig.Database = name
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	p, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		return ErrRecovery
	}
	defer p.Close()
	if e = platform.Migrate(ctx, p); e != nil {
		return ErrRecovery
	}
	tx, e := p.Begin(ctx)
	if e != nil {
		return ErrRecovery
	}
	defer tx.Rollback(ctx)
	var quotedTables []string
	for _, table := range tables {
		quotedTables = append(quotedTables, pgx.Identifier{table}.Sanitize())
	}
	if _, e = tx.Exec(ctx, `TRUNCATE `+strings.Join(quotedTables, ",")+` RESTART IDENTITY`); e != nil {
		return ErrRecovery
	}
	for _, table := range tables {
		cols, e := tx.Query(ctx, `SELECT attname FROM pg_attribute WHERE attrelid=$1::regclass AND attnum>0 AND NOT attisdropped`, table)
		if e != nil {
			return ErrRecovery
		}
		allowed := map[string]bool{}
		for cols.Next() {
			var n string
			cols.Scan(&n)
			allowed[n] = true
		}
		e = cols.Err()
		cols.Close()
		if e != nil {
			return ErrRecovery
		}
		var rows []json.RawMessage
		if json.Unmarshal(a.Files["database/"+table+".json"], &rows) != nil {
			return ErrRecovery
		}
		for _, row := range rows {
			var values map[string]json.RawMessage
			json.Unmarshal(row, &values)
			if len(values) != len(allowed) {
				return ErrRecovery
			}
			for n := range values {
				if !allowed[n] {
					return ErrRecovery
				}
			}
		}
		// The archive already bounds each table and every row is checked above.
		// Restore the validated record set in one statement instead of one
		// database round trip per historical receipt. Keep the same transaction,
		// table order, identity values, row constraints and quarantine path.
		if len(rows) > 0 {
			q := pgx.Identifier{table}.Sanitize()
			if _, e = tx.Exec(ctx, `INSERT INTO `+q+` OVERRIDING SYSTEM VALUE SELECT * FROM json_populate_recordset(NULL::`+q+`,$1::json)`, string(a.Files["database/"+table+".json"])); e != nil {
				return ErrRecovery
			}
		}
	}
	if _, e = tx.Exec(ctx, `SELECT setval(pg_get_serial_sequence('observability_manifests','sequence'),GREATEST(COALESCE((SELECT max(sequence) FROM observability_manifests),0),1),EXISTS(SELECT 1 FROM observability_manifests))`); e != nil {
		return ErrRecovery
	}
	if e = tx.Commit(ctx); e != nil {
		return ErrRecovery
	}
	if e = quarantine(ctx, p); e != nil {
		return ErrRecovery
	}
	root, e := os.OpenRoot(d.Directory)
	if e != nil {
		return ErrRecovery
	}
	defer root.Close()
	if e = root.Mkdir(name, 0700); e != nil {
		return ErrRecovery
	}
	out, e := root.OpenRoot(name)
	if e != nil {
		return ErrRecovery
	}
	defer out.Close()
	defer func() {
		if !ok {
			root.RemoveAll(name)
		}
	}()
	for _, role := range archive.CapsuleRoles(a.Manifest.ExternalCA) {
		if e = out.Mkdir(role, 0700); e != nil {
			return ErrRecovery
		}
	}
	for label, b := range keys {
		parts := strings.Split(label, "/")
		if len(parts) == 4 {
			for _, dir := range []string{parts[0] + "/history", parts[0] + "/history/" + parts[2]} {
				if e = out.Mkdir(dir, 0700); e != nil && !os.IsExist(e) {
					return ErrRecovery
				}
			}
		}
		f, e := out.OpenFile(label, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return ErrRecovery
		}
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		f.Close()
		if e != nil {
			return ErrRecovery
		}
	}
	receipt, _ := json.Marshal(map[string]any{"backup": a.Manifest.ID, "database": name, "mode": "conservative-local", "issuer_trust": "quarantined", "network_activation": false})
	f, e := out.OpenFile("recovery.json", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return ErrRecovery
	}
	_, e = f.Write(receipt)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return ErrRecovery
	}
	d.Database = name
	d.Output = filepath.Join(d.Directory, name)
	ok = true
	return nil
}

// LocalAdminConfig validates connection authority before any network dial.
func LocalAdminConfig(path string) (*pgxpool.Config, error) {
	b, e := archive.ReadRegular(path, 65536)
	if e != nil {
		return nil, ErrRecovery
	}
	cfg, e := pgxpool.ParseConfig(strings.TrimSpace(string(b)))
	if e != nil {
		return nil, ErrRecovery
	}
	host := cfg.ConnConfig.Host
	addr, e := netip.ParseAddr(host)
	if !strings.HasPrefix(host, "/") && (e != nil || !addr.IsLoopback()) {
		return nil, ErrRecovery
	}
	if len(cfg.ConnConfig.Fallbacks) > 0 {
		return nil, ErrRecovery
	}
	cfg.MaxConns = 2
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	return cfg, nil
}
