//go:build integration

package backup_test

import (
	"context"
	"encoding/json"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	backuppg "gatebeam/internal/modules/backup/infrastructure/postgres"
	backups3 "gatebeam/internal/modules/backup/infrastructure/s3"
	"gatebeam/internal/platform/objectstore"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupLongRetentionBeyond2048SpoolEntries(t *testing.T) {
	s, key, p := fixture(t)
	setupBudget := 180 * time.Second
	emulated := os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm"
	if emulated {
		setupBudget *= 12
	}
	ctx, cancel := context.WithTimeout(context.Background(), setupBudget)
	defer cancel()
	endpoint := os.Getenv("GATEBEAM_TEST_S3")
	if endpoint == "" {
		t.Fatal("test S3 required")
	}
	cfg := objectstore.Config{Endpoint: endpoint, Bucket: "backup-long-retention", Region: "auto", AccessKey: "test-access-key", SecretKey: "test-secret-key"}
	client := objectstore.Client(cfg)
	if _, e := client.CreateBucket(ctx, &sdk.CreateBucketInput{Bucket: &cfg.Bucket}); e != nil {
		t.Fatal(e)
	}
	objects, e := backups3.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	catalog := backuppg.Catalog{DB: p}
	service := application.Service{Source: archive.Source{Directory: s.Spool}, Objects: objects, Catalog: catalog}
	policy := application.Policy{Retain: 365 * 24 * time.Hour, MaxAge: time.Hour}
	old := create(t, s)
	if _, e = service.Create(ctx, policy); e != nil {
		t.Fatal(e)
	}
	decoded, _, e := (recovery.Decoder{}).Decode(ctx, old.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	// Seed historical confirmed local cache using actual decryptable age
	// artifacts. Receipts model prior uploads; only the selected and expired
	// objects below require live S3 IO in this regression.
	for i := 0; i < 1025; i++ {
		manifest := decoded.Manifest
		manifest.Created = time.Now().Add(-44 * 24 * time.Hour).Add(time.Duration(i) * time.Nanosecond)
		a, e := archive.Write(ctx, s.Spool, s.Recipient, manifest, decoded.Files)
		if e != nil {
			t.Fatal(e)
		}
		if e = catalog.Confirm(ctx, a); e != nil {
			t.Fatal(e)
		}
	}
	entries, e := os.ReadDir(s.Spool)
	if e != nil || len(entries) <= 2048 {
		t.Fatal("fixture did not cross historical spool entry limit", e)
	}
	if _, e = p.Exec(ctx, `UPDATE backup_runs SET created_at=clock_timestamp()-interval '366 days' WHERE id=$1`, old.Manifest.ID); e != nil {
		t.Fatal(e)
	}
	// Historical artifact generation is fixture preparation on both native and
	// simulated workers. Fresh collection and retention retain their original
	// independent 45s functional deadline.
	cancel()
	ctx, cancel = context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fresh := create(t, s)
	confirmed, e := service.Create(ctx, policy)
	if e != nil {
		t.Fatal("supported long retention blocked fresh upload and cleanup", e)
	}
	if confirmed.ID != fresh.Manifest.ID {
		t.Fatal("current export was not confirmed")
	}
	currentKey := "backups/" + fresh.Manifest.ID + ".age"
	if _, e = client.HeadObject(ctx, &sdk.HeadObjectInput{Bucket: &cfg.Bucket, Key: &currentKey}); e != nil {
		t.Fatal("new current remote backup absent", e)
	}
	oldKey := "backups/" + old.Manifest.ID + ".age"
	if _, e = client.HeadObject(ctx, &sdk.HeadObjectInput{Bucket: &cfg.Bucket, Key: &oldKey}); e == nil {
		t.Fatal("expired confirmed remote backup not retired")
	}
	if _, e = os.Stat(old.Path); !os.IsNotExist(e) {
		t.Fatal("expired local cache not retired")
	}
	var count int
	if e = p.QueryRow(ctx, `SELECT count(*) FROM backup_runs`).Scan(&count); e != nil || count != 1026 {
		t.Fatal("retention lost live confirmed receipts", count, e)
	}
	next := create(t, s)
	if got, e := service.Create(ctx, policy); e != nil || got.ID != next.Manifest.ID {
		t.Fatal("continued current collection blocked by retained cache", e)
	}
}

func TestBackupExportRestoreRowSizeContract(t *testing.T) {
	s, key, p := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	insert := func(size int) {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"payload": strings.Repeat("x", size)})
		if _, e := p.Exec(ctx, `INSERT INTO deployment_candidates(id,body,input_digest) VALUES('11111111-1111-4111-8111-111111111111',$1,$2)`, body, strings.Repeat("a", 64)); e != nil {
			t.Fatal(e)
		}
	}
	insert(9 << 20)
	var rowBytes int
	if e := p.QueryRow(ctx, `SELECT octet_length(row_to_json(t)::text) FROM deployment_candidates t`).Scan(&rowBytes); e != nil {
		t.Fatal(e)
	}
	if rowBytes <= 8<<20 || rowBytes >= 32<<20 {
		t.Fatal("fixture outside mismatched row/table bounds", rowBytes)
	}
	if _, e := s.Export(ctx); e == nil {
		t.Fatal("export published a row that restore must reject")
	}
	if _, e := (archive.Source{Directory: s.Spool}).Latest(ctx, time.Hour); e == nil {
		t.Fatal("rejected oversized row left uploadable artifact")
	}
	var receipts int
	p.QueryRow(ctx, `SELECT count(*) FROM backup_runs`).Scan(&receipts)
	if receipts != 0 {
		t.Fatal("rejected export has success receipt")
	}
	if _, e := p.Exec(ctx, `TRUNCATE deployment_candidates CASCADE`); e != nil {
		t.Fatal(e)
	}
	insert((8 << 20) - 4096)
	if e := p.QueryRow(ctx, `SELECT octet_length(row_to_json(t)::text) FROM deployment_candidates t`).Scan(&rowBytes); e != nil || rowBytes >= 8<<20 {
		t.Fatal("within-boundary fixture invalid", rowBytes, e)
	}
	a := create(t, s)
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	restorer := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	report, e := restorer.Verify(ctx, a.Path, key)
	if e != nil {
		t.Fatal("within-boundary archive failed verification", e)
	}
	if e = restorer.Restore(ctx, report, application.Conservative); e != nil {
		t.Fatal("within-boundary archive failed restoration", e)
	}
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = target.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	defer p.Exec(ctx, `DROP DATABASE `+target.Database+` WITH (FORCE)`)
	var payloadBytes int
	if e = restored.QueryRow(ctx, `SELECT length(body->>'payload') FROM deployment_candidates`).Scan(&payloadBytes); e != nil || payloadBytes != (8<<20)-4096 {
		t.Fatal("near-boundary row changed during recovery", payloadBytes, e)
	}
}

func TestBackupSnapshotRejectsSetOnlySecurityDefinerExecute(t *testing.T) {
	s, _, p := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var schema string
	p.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema)
	login := schema + "_backup"
	capability := schema + "_definer"
	function := schema + ".arm_recovery"
	if _, e := p.Exec(ctx, `CREATE ROLE `+capability+`;GRANT USAGE ON SCHEMA `+schema+` TO `+capability+`;CREATE FUNCTION `+function+`() RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS 'UPDATE `+schema+`.identity_restore_bootstrap SET available=true';REVOKE ALL ON FUNCTION `+function+`() FROM PUBLIC;GRANT EXECUTE ON FUNCTION `+function+`() TO `+capability+`;GRANT `+capability+` TO `+login+` WITH INHERIT FALSE,SET TRUE`); e != nil {
		t.Fatal(e)
	}
	defer p.Exec(context.Background(), `DROP FUNCTION `+function+`();DROP OWNED BY `+capability+`;DROP ROLE `+capability)
	var direct bool
	if e := s.DB.QueryRow(ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, function+"()").Scan(&direct); e != nil || direct {
		t.Fatal("fixture must have no direct or inherited EXECUTE", e)
	}
	conn, e := s.DB.Acquire(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = conn.Exec(ctx, `SET ROLE `+capability+`;SELECT `+function+`();RESET ROLE`); e != nil {
		conn.Release()
		t.Fatal("fixture did not demonstrate SET-only write capability", e)
	}
	conn.Release()
	var armed bool
	p.QueryRow(ctx, `SELECT available FROM identity_restore_bootstrap`).Scan(&armed)
	if !armed {
		t.Fatal("security definer did not exercise effective write authority")
	}
	if e = recovery.CheckSnapshotRole(ctx, s.DB); e == nil {
		t.Fatal("SET-reachable SECURITY DEFINER EXECUTE passed SELECT-only gate")
	}
	if _, e = s.Export(ctx); e == nil {
		t.Fatal("overprivileged exporter produced artifact")
	}
	files, _ := filepath.Glob(filepath.Join(s.Spool, "*.age"))
	if len(files) != 0 {
		t.Fatal("overprivileged export wrote ciphertext")
	}
}

func TestBackupAnnualReceiptCatalogCompactSnapshotRoundTrip(t *testing.T) {
	s, key, p := fixture(t)
	setupBudget := 60 * time.Second
	emulated := os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm"
	if emulated {
		setupBudget *= 12
	}
	ctx, cancel := context.WithTimeout(context.Background(), setupBudget)
	defer cancel()
	baseline := create(t, s)
	manifest, e := json.Marshal(baseline.Manifest)
	if e != nil {
		t.Fatal(e)
	}
	// 8760 hourly delivery receipts model a supported365-day retention window.
	// Past catalog metadata is seeded; this is not8760 crypto/network operations.
	_, e = p.Exec(ctx, `INSERT INTO backup_runs(id,created_at,manifest,cipher_sha256,bytes) SELECT lpad(to_hex(i),64,'0'),clock_timestamp()-i*interval '1 hour',jsonb_set($1::jsonb,'{ID}',to_jsonb(lpad(to_hex(i),64,'0'))),repeat('a',64),1234 FROM generate_series(1,8760) AS g(i)`, manifest)
	if e != nil {
		t.Fatal(e)
	}
	var fullBytes int64
	if e = p.QueryRow(ctx, `SELECT sum(octet_length(row_to_json(t)::text)) FROM backup_runs t`).Scan(&fullBytes); e != nil || fullBytes <= 32<<20 {
		t.Fatal("fixture did not exercise annual full-manifest capacity", fullBytes, e)
	}
	if emulated {
		// Seeding 8760 historical receipts is not the export/restore operation.
		// Its original shared 60s operation deadline begins after preparation.
		cancel()
		ctx, cancel = context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
	}
	a, e := s.Export(ctx)
	if e != nil {
		t.Fatal("annual delivery catalog prevents current backup", e)
	}
	decoded, _, e := (recovery.Decoder{}).Decode(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	body := decoded.Files["database/backup_runs.json"]
	if len(body) > 32<<20 {
		t.Fatal("compact receipt projection exceeded unchanged table limit")
	}
	var rows []struct {
		ID       string         `json:"id"`
		Manifest map[string]any `json:"manifest"`
	}
	if json.Unmarshal(body, &rows) != nil || len(rows) != 8760 {
		t.Fatal("recovery projection lost receipt history")
	}
	for _, row := range rows {
		if _, ok := row.Manifest["Files"]; ok {
			t.Fatal("redundant historical per-file manifest retained")
		}
		if row.Manifest["detail_status"] != "omitted_for_recovery" || row.Manifest["artifact_verification"] != "required" {
			t.Fatal("compact receipt could be mistaken for verified restorable archive")
		}
		if row.Manifest["Schema"] != baseline.Manifest.Schema || row.Manifest["Epoch"] != s.Epoch || row.Manifest["Recipient"] != s.Recipient {
			t.Fatal("receipt projection lost schema/epoch/recipient provenance")
		}
	}
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	restorer := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	report, e := restorer.Verify(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	restoreStarted := time.Now()
	if e = restorer.Restore(ctx, report, application.Conservative); e != nil {
		t.Fatalf("annual compact receipt restore failed: deadline_expired=%t elapsed=%s error=%v", ctx.Err() != nil, time.Since(restoreStarted), e)
	}
	t.Logf("annual compact receipt restore completed: elapsed=%s", time.Since(restoreStarted))
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = target.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	defer p.Exec(ctx, `DROP DATABASE `+target.Database+` WITH (FORCE)`)
	var retained int
	if e = restored.QueryRow(ctx, `SELECT count(*) FROM backup_runs WHERE bytes=1234 AND cipher_sha256=repeat('a',64) AND manifest->>'detail_status'='omitted_for_recovery' AND manifest->>'artifact_verification'='required' AND NOT (manifest ? 'Files')`).Scan(&retained); e != nil || retained != 8760 {
		t.Fatal("restored delivery metadata lost history or verification boundary", retained, e)
	}
	t.Logf("8760 receipts: full catalog JSON=%d bytes; recovery projection=%d bytes", fullBytes, len(body))
}

func TestBackupReceiptProjectionUsesCallerSnapshot(t *testing.T) {
	s, _, p := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a := create(t, s)
	if e := (backuppg.Catalog{DB: p}).Confirm(ctx, a); e != nil {
		t.Fatal(e)
	}
	var captured transaction.Scope
	e := platform.NewRunner(s.DB).Within(ctx, func(sc transaction.Scope) error {
		captured = sc
		if e := platform.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
			if _, e := tx.Exec(ctx, `SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY`); e != nil {
				return e
			}
			var before string
			return tx.QueryRow(ctx, `SELECT manifest->>'Snapshot' FROM backup_runs WHERE id=$1`, a.Manifest.ID).Scan(&before)
		}); e != nil {
			return e
		}
		if _, e := p.Exec(ctx, `UPDATE backup_runs SET manifest=jsonb_set(manifest,'{Snapshot}',to_jsonb('later committed snapshot'::text)) WHERE id=$1`, a.Manifest.ID); e != nil {
			return e
		}
		// DB deliberately points to a different connection pool: using that pool
		// instead of Scope would observe the later commit and fail this assertion.
		rows, e := application.ExportRecoveryReceiptsWithin(sc, backuppg.Catalog{DB: p})
		if e != nil {
			return e
		}
		if len(rows) != 1 || rows[0].Manifest.Snapshot != a.Manifest.Snapshot {
			t.Fatal("owner receipt projection escaped the caller repeatable-read snapshot")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	var live string
	if e = p.QueryRow(ctx, `SELECT manifest->>'Snapshot' FROM backup_runs WHERE id=$1`, a.Manifest.ID).Scan(&live); e != nil || live != "later committed snapshot" {
		t.Fatal("fixture did not commit an interleaving write", e)
	}
	if _, e = (backuppg.Catalog{DB: p}).RecoveryReceiptsWithin(captured); e == nil {
		t.Fatal("expired Scope fell back to live catalog pool")
	}
}
