package parquet_test

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	spool "gatebeam/internal/modules/observability/infrastructure/parquet"
	pq "github.com/parquet-go/parquet-go"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDurableCompressedObjectImmutableReplayAndCapacity(t *testing.T) {
	dir := t.TempDir()
	w, e := spool.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	id := strings.Repeat("a", 64)
	rows := []domain.Event{{SiteID: "11111111-1111-4111-8111-111111111111", Time: time.Now().UTC(), Micros: 42}}
	objects, e := w.Persist(context.Background(), id, rows)
	if e != nil || len(objects) != 1 {
		t.Fatal(objects, e)
	}
	decoded, e := pq.ReadFile[spool.Row](filepath.Join(dir, objects[0].Key))
	if e != nil || len(decoded) != 1 || decoded[0].Micros != 42 {
		t.Fatal(decoded, e)
	}
	same, e := w.Persist(context.Background(), id, rows)
	if e != nil || same[0].Checksum != objects[0].Checksum {
		t.Fatal(same, e)
	}
	rows[0].Micros++
	if _, e = w.Persist(context.Background(), id, rows); !errors.Is(e, domain.ErrSourceChanged) {
		t.Fatal("immutable object overwritten", e)
	}
	w.MaxBytes = 1
	if _, e = w.Persist(context.Background(), id, rows); !errors.Is(e, domain.ErrCapacity) {
		t.Fatal("spool capacity ignored", e)
	}
}

func TestSpoolDepthIsBounded(t *testing.T) {
	dir := t.TempDir()
	w, e := spool.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Join(dir, "site", "date", "hour", "unexpected-depth"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = w.Persist(context.Background(), strings.Repeat("b", 64), nil); !errors.Is(e, domain.ErrCapacity) {
		t.Fatalf("unbounded spool depth accepted: %v", e)
	}
}

func TestRestoredWideSpoolRejectsGlobalEntryLimit(t *testing.T) {
	dir := t.TempDir()
	w, e := spool.New(dir)
	if e != nil {
		t.Fatal(e)
	}
	w.MaxFiles = 4*domain.MaxRows + 1 + 66
	for i := range 512 {
		if e = os.WriteFile(filepath.Join(dir, fmt.Sprintf("restored-%04d", i)), nil, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = w.Persist(context.Background(), strings.Repeat("c", 64), nil); !errors.Is(e, domain.ErrCapacity) {
		t.Fatal("restored wide spool bypassed entry limit", e)
	}
}
