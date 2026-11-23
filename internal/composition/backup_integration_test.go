//go:build integration

package composition

import (
	"context"
	"encoding/json"
	"filippo.io/age"
	"fmt"
	"gatebeam/internal/modules/backup/application"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	backuppg "gatebeam/internal/modules/backup/infrastructure/postgres"
	backups3 "gatebeam/internal/modules/backup/infrastructure/s3"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/objectstore"
	"gatebeam/internal/platform/testkit"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupScheduledCollectionAndWorkerUpload(t *testing.T) {
	p := testkit.Postgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var schema string
	p.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema)
	role := schema + "_snapshot"
	if _, e := p.Exec(ctx, `CREATE ROLE `+role+` LOGIN PASSWORD 'owned-only';GRANT USAGE ON SCHEMA `+schema+` TO `+role+`;GRANT SELECT ON ALL TABLES IN SCHEMA `+schema+` TO `+role); e != nil {
		t.Fatal(e)
	}
	defer p.Exec(context.Background(), `DROP OWNED BY `+role+`;DROP ROLE `+role)
	dir := t.TempDir()
	key, _ := age.GenerateX25519Identity()
	identity := filepath.Join(dir, "private")
	os.WriteFile(identity, []byte(key.String()), 0600)
	caps := filepath.Join(dir, "capsules")
	os.Mkdir(caps, 0700)
	online, _ := age.GenerateX25519Identity()
	os.WriteFile(identity, []byte(online.String()), 0600)
	for _, r := range archive.Roles {
		os.Mkdir(filepath.Join(caps, r), 0700)
		if e := archive.ExportCapsule(ctx, caps, r, "epoch", key.Recipient().String(), func() map[string]string {
			paths := map[string]string{}
			for _, n := range archive.AllowedFiles(r) {
				paths[n] = identity
			}
			return paths
		}()); e != nil {
			t.Fatal(e)
		}
	}
	cfg := p.Config().ConnConfig.Copy()
	cfg.User = role
	cfg.Password = "owned-only"
	dbfile := filepath.Join(dir, "snapshot-db")
	os.WriteFile(dbfile, []byte(fmt.Sprintf("host=%s port=%d user=%s password=owned-only dbname=%s sslmode=disable search_path=%s", cfg.Host, cfg.Port, role, cfg.Database, schema)), 0600)
	export := bootstrap.Config{Mode: "backup-export", DatabaseFile: dbfile, BackupRecipient: key.Recipient().String(), BackupEpoch: "epoch", BackupCapsuleDirectory: caps, BackupSpoolDirectory: dir}
	// The timer's one-shot path opens only its dedicated SELECT login and
	// collects fresh state each invocation; no snapshot supplied by the worker.
	if e := Run(ctx, "backup-export", export); e != nil {
		t.Fatal(e)
	}
	endpoint := os.Getenv("GATEBEAM_TEST_S3")
	if endpoint == "" {
		t.Fatal("test S3 required")
	}
	objectcfg := objectstore.Config{Endpoint: endpoint, Bucket: "scheduled-owned-test", Region: "auto", AccessKey: "test-access-key", SecretKey: "test-secret-key"}
	client := objectstore.Client(objectcfg)
	if _, e := client.CreateBucket(ctx, &sdk.CreateBucketInput{Bucket: &objectcfg.Bucket}); e != nil {
		t.Fatal(e)
	}
	objects, e := backups3.New(objectcfg)
	if e != nil {
		t.Fatal(e)
	}
	svc := &application.Service{Source: archive.Source{Directory: dir}, Objects: objects, Catalog: backuppg.Catalog{DB: p}}
	ticks := make(chan time.Time, 1)
	done := make(chan error, 1)
	loopctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		done <- backupLoop(loopctx, svc, application.Policy{Retain: 24 * time.Hour, MaxAge: time.Hour}, ticks)
	}()
	wait := func(want int) {
		t.Helper()
		for i := 0; i < 100; i++ {
			var count int
			p.QueryRow(ctx, `SELECT count(*) FROM backup_runs`).Scan(&count)
			if count == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("scheduled worker did not confirm backup")
	}
	wait(1)
	if _, e = p.Exec(ctx, `INSERT INTO ingress_groups VALUES(gen_random_uuid(),'scheduled-update',1)`); e != nil {
		t.Fatal(e)
	}
	if e = Run(ctx, "backup-export", export); e != nil {
		t.Fatal(e)
	}
	ticks <- time.Now()
	wait(2)
	stop()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("backup loop cancellation blocked")
	}
	var body []byte
	if e = p.QueryRow(ctx, `SELECT manifest FROM backup_runs ORDER BY created_at DESC LIMIT 1`).Scan(&body); e != nil {
		t.Fatal(e)
	}
	var manifest application.Manifest
	if json.Unmarshal(body, &manifest) != nil || manifest.Snapshot == "" {
		t.Fatal("snapshot provenance missing")
	}
}
