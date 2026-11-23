//go:build integration

package backup_test

import (
	"context"
	"encoding/json"
	"fmt"
	"gatebeam/internal/integration/recovery"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBackupNativeLinuxExporterHasOnlyReadOnlySnapshotAndCiphertextMounts(t *testing.T) {
	s, key, p := fixture(t)
	binary := os.Getenv("GATEBEAM_I4_BINARY")
	container := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if binary == "" || container == "" {
		t.Fatal("fresh Linux binary and owned PG container required")
	}
	ctx := context.Background()
	if _, e := p.Exec(ctx, `INSERT INTO ingress_groups VALUES(gen_random_uuid(),'native-cli-current-state',1)`); e != nil {
		t.Fatal(e)
	}
	cfgDir, spool := t.TempDir(), t.TempDir()
	cfg := s.DB.Config().ConnConfig
	dsn := fmt.Sprintf("host=127.0.0.1 port=5432 user=%s password=owned-only dbname=%s sslmode=disable search_path=%s", cfg.User, cfg.Database, cfg.RuntimeParams["search_path"])
	if e := os.WriteFile(filepath.Join(cfgDir, "database"), []byte(dsn), 0600); e != nil {
		t.Fatal(e)
	}
	config := bootstrap.Config{Mode: "backup-export", Environment: "production", DatabaseFile: "/config/database", BackupRecipient: s.Recipient, BackupEpoch: s.Epoch, BackupCapsuleDirectory: "/capsules", BackupSpoolDirectory: "/spool"}
	b, _ := json.Marshal(config)
	os.WriteFile(filepath.Join(cfgDir, "export.json"), b, 0600)
	// Only ciphertext capsules, the SELECT-only login, binary and empty output
	// are mounted. Offline recovery and API/edge/CA private files stay on host.
	docker(t, "run", "--rm", "--network", "container:"+container, "--label", "gatebeam.o4.run="+os.Getenv("GATEBEAM_TEST_BACKUP_RUN"), "--memory", "512m", "--cpus", "1", "--pids-limit", "32", "--read-only", "--tmpfs", "/tmp:size=16m", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "-v", binary+":/gatebeam:ro", "-v", cfgDir+":/config:ro", "-v", s.Capsules+":/capsules:ro", "-v", spool+":/spool", "--entrypoint", "/gatebeam", "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606", "--config", "/config/export.json")
	a, e := (archive.Source{Directory: spool}).Latest(ctx, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	decoded, _, e := (recovery.Decoder{}).Decode(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	var rows []map[string]any
	if json.Unmarshal(decoded.Files["database/ingress_groups.json"], &rows) != nil || len(rows) != 1 {
		t.Fatal("native exporter did not collect current database")
	}
}
