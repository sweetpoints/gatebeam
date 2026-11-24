// Package recovery coordinates controlled data-only snapshots and owner ports.
// This adapter is available only to the dedicated read-only local exporter.
package recovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/modules/backup/domain"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	backuppg "gatebeam/internal/modules/backup/infrastructure/postgres"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"reflect"
	"strings"
	"time"
)

var ErrRecovery = errors.New("local recovery unavailable")

// Export and offline verification use the same row contract. A valid database
// value is not necessarily within the bounded recovery format's capacity.
func validSnapshotRow(row []byte) bool {
	if len(row) > domain.MaxRow {
		return false
	}
	var fields map[string]json.RawMessage
	return json.Unmarshal(row, &fields) == nil && len(fields) > 0 && len(fields) <= 128
}

type Snapshot struct {
	DB                                *pgxpool.Pool
	Capsules, Epoch, Recipient, Spool string
	ExternalCA                        bool
}

func schemaDigest() string { c, _ := SchemaContract(CurrentSchema); return c.Digest }
func CheckSnapshotRole(ctx context.Context, p *pgxpool.Pool) error {
	var safe bool
	e := p.QueryRow(ctx, `WITH reachable AS(SELECT * FROM pg_roles WHERE rolname=current_user OR rolname=session_user OR pg_has_role(session_user,oid,'SET')) SELECT NOT EXISTS(SELECT 1 FROM reachable r WHERE rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls OR EXISTS(SELECT 1 FROM pg_roles cap WHERE pg_has_role(r.oid,cap.oid,'MEMBER WITH ADMIN OPTION') OR (cap.rolname IN('pg_read_server_files','pg_write_server_files','pg_execute_server_program') AND pg_has_role(r.oid,cap.oid,'USAGE'))) OR EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname=current_schema() AND (pg_has_role(r.oid,n.nspowner,'USAGE') OR has_schema_privilege(r.oid,n.oid,'CREATE'))) OR EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN('r','p') AND (pg_has_role(r.oid,c.relowner,'USAGE') OR has_table_privilege(r.oid,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR has_any_column_privilege(r.oid,c.oid,'INSERT,UPDATE,REFERENCES')))) AND NOT EXISTS(SELECT 1 FROM reachable r CROSS JOIN pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace WHERE f.prosecdef AND n.nspname NOT IN('pg_catalog','information_schema') AND has_function_privilege(r.oid,f.oid,'EXECUTE'))`).Scan(&safe)
	if e != nil || !safe {
		return ErrRecovery
	}
	return nil
}
func (s Snapshot) Export(ctx context.Context) (application.Artifact, error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if e := CheckSnapshotRole(ctx, s.DB); e != nil {
		return application.Artifact{}, e
	}
	caps, e := archive.ReadCapsulesForCA(s.Capsules, s.Epoch, s.Recipient, s.ExternalCA)
	if e != nil {
		return application.Artifact{}, e
	}
	var snapshot string
	var now time.Time
	files := map[string][]byte{}
	total := 0
	var contract Contract
	e = platform.NewRunner(s.DB).Within(ctx, func(sc transaction.Scope) error {
		if err := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`); err != nil {
				return ErrRecovery
			}
			var version int64
			if err := tx.QueryRow(ctx, `SELECT max(version_id) FROM goose_db_version WHERE is_applied`).Scan(&version); err != nil {
				return ErrRecovery
			}
			var err error
			contract, err = SchemaContract(version)
			if err != nil {
				return ErrRecovery
			}
			if err := tx.QueryRow(ctx, `SELECT current_database()||'/'||current_schema()||'/'||pg_current_snapshot()::text,transaction_timestamp()`).Scan(&snapshot, &now); err != nil {
				return ErrRecovery
			}
			for _, table := range contract.Tables {
				if table == "backup_runs" {
					continue
				}
				rows, e := tx.Query(ctx, `SELECT row_to_json(t) FROM `+pgx.Identifier{table}.Sanitize()+` t`)
				if e != nil {
					return ErrRecovery
				}
				var out bytes.Buffer
				out.WriteByte('[')
				count := 0
				for rows.Next() {
					var b []byte
					if e = rows.Scan(&b); e != nil {
						rows.Close()
						return ErrRecovery
					}
					if !validSnapshotRow(b) {
						rows.Close()
						return ErrRecovery
					}
					if count > 0 {
						out.WriteByte(',')
					}
					out.Write(b)
					count++
					if out.Len() > domain.MaxFile || count > domain.MaxRows {
						rows.Close()
						return ErrRecovery
					}
				}
				e = rows.Err()
				rows.Close()
				if e != nil {
					return ErrRecovery
				}
				out.WriteByte(']')
				total += out.Len()
				if total > domain.MaxArchive-(16<<20) {
					return ErrRecovery
				}
				files["database/"+table+".json"] = out.Bytes()
			}

			return nil
		}); err != nil {
			return err
		}
		receipts, err := application.ExportRecoveryReceiptsWithin(sc, backuppg.Catalog{DB: s.DB})
		if err != nil {
			return err
		}
		b, err := json.Marshal(receipts)
		if err != nil || len(b) > domain.MaxFile {
			return ErrRecovery
		}
		total += len(b)
		if total > domain.MaxArchive-(16<<20) {
			return ErrRecovery
		}
		files["database/backup_runs.json"] = b
		return nil
	})
	if e != nil {
		return application.Artifact{}, ErrRecovery
	}
	again, e := archive.ReadCapsulesForCA(s.Capsules, s.Epoch, s.Recipient, s.ExternalCA)
	if e != nil || !reflect.DeepEqual(caps, again) {
		return application.Artifact{}, ErrRecovery
	}
	for n, b := range caps {
		files[n] = b
	}
	return archive.Write(ctx, s.Spool, s.Recipient, application.Manifest{Version: 1, ExternalCA: s.ExternalCA, Created: now, Snapshot: snapshot, Epoch: s.Epoch, Schema: contract.Digest}, files)
}
func validate(a application.Archive) error {
	contract, e := contractByDigest(a.Manifest.Schema)
	if e != nil || a.Manifest.Validate() != nil || len(a.Files) < len(contract.Tables)+4 || len(a.Files) > len(contract.Tables)+4*(archive.MaxHistory+1) {
		return ErrRecovery
	}
	allowed := map[string]bool{}
	for _, table := range contract.Tables {
		allowed["database/"+table+".json"] = true
	}
	for name := range a.Files {
		if !allowed[name] && (!strings.HasPrefix(name, "capsules/") || !domain.ValidName(name)) {
			return ErrRecovery
		}
	}
	for _, table := range contract.Tables {
		b, ok := a.Files["database/"+table+".json"]
		if !ok || !json.Valid(b) {
			return ErrRecovery
		}
		var rows []json.RawMessage
		if json.Unmarshal(b, &rows) != nil || len(rows) > domain.MaxRows {
			return ErrRecovery
		}
		for _, row := range rows {
			if !validSnapshotRow(row) {
				return ErrRecovery
			}
		}
	}
	return nil
}

// Decoder checks the compiled database contract and every nested capsule as
// part of Verify, before any database/directory may be created.
type Decoder struct{}

func (Decoder) Decode(ctx context.Context, source, identity string) (application.Archive, string, error) {
	a, d, e := (archive.Decoder{}).Decode(ctx, source, identity)
	if e != nil {
		return a, d, e
	}
	if e = validate(a); e != nil {
		return application.Archive{}, "", e
	}
	if _, e = archive.OpenCapsulesForCA(a.Files, a.Manifest.Epoch, identity, a.Manifest.ExternalCA); e != nil {
		return application.Archive{}, "", e
	}
	return a, d, nil
}
