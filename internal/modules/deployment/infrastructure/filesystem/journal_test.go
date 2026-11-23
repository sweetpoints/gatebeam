package filesystem_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func artifact(data string) edge.Artifact {
	h := sha256.New()
	fmt.Fprintf(h, "%d:%s:%d:", 10, "nginx.conf", len(data))
	h.Write([]byte(data))
	id := hex.EncodeToString(h.Sum(nil))
	return edge.Artifact{ID: id, Digest: id, Files: map[string][]byte{"nginx.conf": []byte(data)}}
}
func TestDurableStageSwitchAndJournal(t *testing.T) {
	root := t.TempDir()
	s, e := fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	a := artifact("events{}")
	path, e := s.Stage(ctx, a)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Switch(ctx, a.ID); e != nil {
		t.Fatal(e)
	}
	actual, e := os.ReadFile(filepath.Join(root, "current", "nginx.conf"))
	if e != nil || string(actual) != "events{}" {
		t.Fatalf("atomic current %s %v", actual, e)
	}
	j := domain.ApplyJournal{CandidateID: "candidate", ArtifactID: a.ID, State: domain.Applying, ReceiptPending: true}
	if e = s.Save(ctx, j); e != nil {
		t.Fatal(e)
	}
	reopened, e := fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	got, e := reopened.Load(ctx)
	if e != nil || got != j {
		t.Fatalf("journal durability %+v %v", got, e)
	}
	if e = os.WriteFile(filepath.Join(path, "nginx.conf"), []byte("tampered"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Stage(ctx, a); e == nil {
		t.Fatal("existing tampered artifact reused")
	}
	a.Files["../escape"] = []byte("bad")
	if _, e = s.Stage(ctx, a); e == nil {
		t.Fatal("path traversal staged")
	}
}
func TestCrossInstanceLockIsBounded(t *testing.T) {
	root := t.TempDir()
	a, _ := fs.New(root)
	b, _ := fs.New(root)
	unlock, e := a.Lock(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	defer unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, e = b.Lock(ctx); e == nil {
		t.Fatal("concurrent executor acquired lock")
	}
}

func TestJournalRetainsFsyncedPhaseHistory(t *testing.T) {
	root := t.TempDir()
	s, e := fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	j := domain.ApplyJournal{CandidateID: "candidate", State: domain.Preparing}
	if e = s.Save(context.Background(), j); e != nil {
		t.Fatal(e)
	}
	j.State = domain.Validated
	if e = s.Save(context.Background(), j); e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(filepath.Join(root, "apply-journal.jsonl"))
	if e != nil {
		t.Fatal(e)
	}
	if strings.Count(string(b), "\n") != 2 || !strings.Contains(string(b), `"state":"preparing"`) || !strings.Contains(string(b), `"state":"validated"`) {
		t.Fatalf("phase history not retained: %s", b)
	}
}
