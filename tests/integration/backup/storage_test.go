//go:build integration

package backup_test

import (
	"bytes"
	"context"
	"encoding/json"
	"gatebeam/internal/modules/backup/application"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	backuppg "gatebeam/internal/modules/backup/infrastructure/postgres"
	backups3 "gatebeam/internal/modules/backup/infrastructure/s3"
	"gatebeam/internal/platform/objectstore"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	"io"
	"os"
	"testing"
	"time"
)

func TestCurrentSnapshotsVerifiedS3AndRetention(t *testing.T) {
	s, key, p := fixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	endpoint := os.Getenv("GATEBEAM_TEST_S3")
	if endpoint == "" {
		t.Fatal("check-backup.sh test S3 required")
	}
	cfg := objectstore.Config{Endpoint: endpoint, Bucket: "backup-owned-test", Region: "auto", AccessKey: "test-access-key", SecretKey: "test-secret-key"}
	client := objectstore.Client(cfg)
	if _, e := client.CreateBucket(ctx, &sdk.CreateBucketInput{Bucket: &cfg.Bucket}); e != nil {
		t.Fatal(e)
	}
	store, e := backups3.New(cfg)
	if e != nil {
		t.Fatal(e)
	}
	svc := application.Service{Source: archive.Source{Directory: s.Spool}, Objects: store, Catalog: backuppg.Catalog{DB: p}}
	policy := application.Policy{Retain: 24 * time.Hour, MaxAge: time.Hour}
	old := create(t, s)
	if _, e = svc.Create(ctx, policy); e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO ingress_groups VALUES(gen_random_uuid(),'new since first snapshot',1)`)
	if e != nil {
		t.Fatal(e)
	}
	fresh := create(t, s)
	if fresh.Manifest.ID == old.Manifest.ID {
		t.Fatal("scheduled collection reused stale snapshot")
	}
	if _, e = svc.Create(ctx, policy); e != nil {
		t.Fatal(e)
	}
	object := "backups/" + fresh.Manifest.ID + ".age"
	v, e := client.GetObject(ctx, &sdk.GetObjectInput{Bucket: &cfg.Bucket, Key: &object})
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(v.Body)
	v.Body.Close()
	if e != nil || archive.Digest(body) != fresh.SHA256 {
		t.Fatal("remote ciphertext differs")
	}
	download := t.TempDir() + "/download.age"
	os.WriteFile(download, body, 0600)
	a, _, e := (archive.Decoder{}).Decode(ctx, download, key)
	if e != nil {
		t.Fatal(e)
	}
	var groups []map[string]any
	if json.Unmarshal(a.Files["database/ingress_groups.json"], &groups) != nil || len(groups) != 1 {
		t.Fatal("fresh snapshot did not contain committed DB state")
	}
	// A conflicting/corrupt object at an immutable key cannot become a
	// successful receipt, even when the remote service returns it successfully.
	corrupt := create(t, s)
	badKey := "backups/" + corrupt.Manifest.ID + ".age"
	bad := []byte("corrupt")
	_, e = client.PutObject(ctx, &sdk.PutObjectInput{Bucket: &cfg.Bucket, Key: &badKey, Body: bytes.NewReader(bad)})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Create(ctx, policy); e == nil {
		t.Fatal("corrupt remote object confirmed")
	}
	var exists bool
	p.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM backup_runs WHERE id=$1)`, corrupt.Manifest.ID).Scan(&exists)
	if exists {
		t.Fatal("corrupt object has success receipt")
	}
	client.DeleteObject(ctx, &sdk.DeleteObjectInput{Bucket: &cfg.Bucket, Key: &badKey})
	if _, e = svc.Create(ctx, policy); e != nil {
		t.Fatal(e)
	}
	// Catalog uses export time, not upload time; retiring old runs waits for a
	// successful verified upload and never removes the selected latest object.
	if _, e = p.Exec(ctx, `UPDATE backup_runs SET created_at=clock_timestamp()-interval '2 days' WHERE id=$1`, old.Manifest.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = svc.Create(ctx, policy); e != nil {
		t.Fatal(e)
	}
	object = "backups/" + old.Manifest.ID + ".age"
	if _, e = client.HeadObject(ctx, &sdk.HeadObjectInput{Bucket: &cfg.Bucket, Key: &object}); e == nil {
		t.Fatal("expired remote backup retained")
	}
	if _, e = os.Stat(old.Path); !os.IsNotExist(e) {
		t.Fatal("expired local ciphertext retained")
	}
}
