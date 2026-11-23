package application

import (
	"context"
	"errors"
	"gatebeam/internal/modules/backup/domain"
	"strings"
	"testing"
	"time"
)

type source struct {
	a       Artifact
	removed bool
}

func (s *source) Latest(context.Context, time.Duration) (Artifact, error) { return s.a, nil }
func (s *source) Cleanup(context.Context, string) error                   { s.removed = true; return nil }

type objects struct {
	fail    bool
	deleted bool
}

func (o *objects) PutVerified(context.Context, Artifact) error {
	if o.fail {
		return errors.New("upload unavailable")
	}
	return nil
}
func (o *objects) Delete(context.Context, string) error { o.deleted = true; return nil }

type catalog struct {
	confirmed bool
	expired   bool
	forgot    bool
}

func (c *catalog) Confirm(context.Context, Artifact) error { c.confirmed = true; return nil }
func (c *catalog) Expired(context.Context, time.Time, string) ([]string, error) {
	c.expired = true
	return []string{strings.Repeat("a", 64)}, nil
}
func (c *catalog) Forget(context.Context, string) error { c.forgot = true; return nil }
func TestFailedUploadCannotConfirmOrDeleteLastBackup(t *testing.T) {
	now := time.Now()
	m := Manifest{Version: 1, ID: strings.Repeat("b", 64), Schema: strings.Repeat("c", 64), Created: now, Snapshot: "1:2:", Epoch: "epoch", Files: []domain.File{{Name: "capsules/api.age", Bytes: 1, SHA256: strings.Repeat("a", 64)}}}
	src := &source{a: Artifact{Manifest: m, SHA256: strings.Repeat("d", 64), Bytes: 100}}
	obj := &objects{fail: true}
	cat := &catalog{}
	svc := Service{Source: src, Objects: obj, Catalog: cat}
	policy := Policy{Retain: 24 * time.Hour, MaxAge: time.Hour}
	if _, e := svc.Create(context.Background(), policy); e == nil {
		t.Fatal("upload failure ignored")
	}
	if cat.confirmed || cat.expired || cat.forgot || obj.deleted || src.removed {
		t.Fatal("failed upload advanced confirmation or retention")
	}
	obj.fail = false
	if _, e := svc.Create(context.Background(), policy); e != nil {
		t.Fatal(e)
	}
	if !cat.confirmed || !cat.forgot || !obj.deleted || !src.removed {
		t.Fatal("verified upload did not retain/retire")
	}
}
