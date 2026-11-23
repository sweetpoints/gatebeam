//go:build integration

package logfile

import (
	"errors"
	"gatebeam/internal/modules/observability/domain"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRetirementSyncFailurePreservesDatabaseIntent(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	dir := t.TempDir()
	source, e := Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer source.Close()
	seg := domain.Segment{ID: strings.Repeat("a", 64), Path: retiredName, Closed: true}
	if e = os.WriteFile(filepath.Join(dir, retiredName+".closed"), nil, 0600); e != nil {
		t.Fatal(e)
	}
	var pending []repo.Retirement
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error {
		if e := r.BeginRetirement(sc, seg); e != nil {
			return e
		}
		var e error
		pending, e = r.Retirements(sc)
		return e
	}); e != nil || len(pending) != 1 {
		t.Fatal(e)
	}
	finish := func(syncDirectory func() error) error {
		if e := source.removeRetired(pending[0].Segment, syncDirectory); e != nil {
			return e
		}
		return tx.Within(t.Context(), func(sc transaction.Scope) error { return r.FinishRetirement(sc, pending[0].ID) })
	}
	failure := errors.New("injected directory sync failure")
	if e = finish(func() error { return failure }); !errors.Is(e, failure) {
		t.Fatal("failed barrier accepted", e)
	}
	var retired bool
	if e = p.QueryRow(t.Context(), `SELECT retired FROM observability_segments WHERE id=$1`, pending[0].ID).Scan(&retired); e != nil || retired {
		t.Fatal("intent finalized before durability barrier", retired, e)
	}
	if _, e = os.Stat(filepath.Join(dir, retiredName+".closed")); !os.IsNotExist(e) {
		t.Fatal("marker not removed before failed barrier", e)
	}
	if e = finish(source.syncRetirementDirectory); e != nil {
		t.Fatal(e)
	}
	if e = p.QueryRow(t.Context(), `SELECT retired FROM observability_segments WHERE id=$1`, pending[0].ID).Scan(&retired); e != nil || !retired {
		t.Fatal("durable retry not finalized", retired, e)
	}
}
