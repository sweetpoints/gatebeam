//go:build integration

package backup_test

import (
	"context"
	"encoding/json"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestJobTargetsSnapshotRestoreQuarantinesLeases(t *testing.T) {
	snapshot, key, p := fixture(t)
	target := jobs.ClaimTarget{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 7}
	if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		_, err := jobs.New(p).EnqueueTargetWithin(sc, "deployment.node.apply.v1", "release", json.RawMessage(`{}`), target)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	artifact := create(t, snapshot)
	decoded, _, err := (recovery.Decoder{}).Decode(t.Context(), artifact.Path, key)
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		NodeID string `json:"target_node_id"`
		Epoch  uint64 `json:"target_node_epoch"`
	}
	if err = json.Unmarshal(decoded.Files["database/jobs.json"], &rows); err != nil || len(rows) != 1 || rows[0].NodeID != target.NodeID || rows[0].Epoch != target.Epoch {
		t.Fatalf("target binding omitted from encrypted snapshot: %+v %v", rows, err)
	}
	destination := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	restorer := application.Restorer{Decoder: recovery.Decoder{}, Destination: destination}
	report, err := restorer.Verify(t.Context(), artifact.Path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err = restorer.Restore(t.Context(), report, application.Conservative); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP DATABASE `+destination.Database+` WITH (FORCE)`) })
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = destination.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var count int
	if err = restored.QueryRow(t.Context(), `SELECT count(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("restored snapshot replayed node work before controlled re-enrollment", err)
	}
}
