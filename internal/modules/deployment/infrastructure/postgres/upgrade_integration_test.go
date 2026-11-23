//go:build integration

package postgres_test

import (
	"bytes"
	"encoding/json"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/testkit"
	"strings"
	"testing"
)

func TestUpgradeJournalFencesConcurrentBatchesAndStaleOwner(t *testing.T) {
	p := testkit.Postgres(t)
	s := repo.UpgradeStore{Pool: p}
	ctx := t.Context()
	r := upgrade.Run{Plan: upgrade.Plan{ID: "33333333-3333-4333-8333-333333333333"}, Owner: "projects/owned/zones/us-west1-c/instances/old", Revision: 1, State: "running"}
	if e := s.Create(ctx, r); e != nil {
		t.Fatal(e)
	}
	other := r
	other.Plan.ID = "44444444-4444-4444-8444-444444444444"
	if e := s.Create(ctx, other); e == nil {
		t.Fatal("concurrent active upgrade")
	}
	r.Revision = 2
	r.State = "paused"
	if e := s.Save(ctx, r, 1); e != nil {
		t.Fatal(e)
	}
	next := r
	next.Revision = 3
	next.Owner = "projects/owned/zones/us-west1-c/instances/new"
	next.State = "running"
	if e := s.Save(ctx, next, 2); e != nil {
		t.Fatal(e)
	}
	r.Revision = 3
	if e := s.Save(ctx, r, 2); e == nil {
		t.Fatal("stale owner resumed after takeover")
	}
	got, e := s.Load(ctx, r.Plan.ID)
	if e != nil || got.Owner != next.Owner || got.State != "running" {
		t.Fatal(got, e)
	}
}

func TestUpgradeImageApprovalRequiresRecordedPreviousPolicy(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	s := repo.UpgradeStore{Pool: p}
	id := "11111111-1111-4111-8111-111111111111"
	old := strings.Repeat("a", 64)
	next := strings.Repeat("b", 64)
	n := domain.NodeDeployment{Node: domain.NodeRef{ID: id, Epoch: 1}, Roles: map[string]domain.RoleDeployment{"management": {Image: "registry.test/api@sha256:" + old}}}
	step := upgrade.Step{ID: "33333333-3333-4333-8333-333333333333-001", Kind: "approve-images", Node: n.Node, Targets: []domain.NodeDeployment{n}, Images: map[string]string{"management": "registry.test/api@sha256:" + next}}
	run := upgrade.Run{Plan: upgrade.Plan{ID: step.ID[:36]}, Owner: "owned", Revision: 1, State: "running", Pending: &step}
	if e := s.Create(ctx, run); e != nil {
		t.Fatal(e)
	}
	insert := func(digest string) {
		body, _ := json.Marshal(map[string]any{"BridgeImages": map[string]string{"management": "sha256:" + digest}})
		if _, e := p.Exec(ctx, `INSERT INTO deployment_nodes(id,epoch,principal,registration,enabled) VALUES($1,1,'owned-principal',$2,true) ON CONFLICT(id) DO UPDATE SET registration=$2`, id, body); e != nil {
			t.Fatal(e)
		}
	}
	insert(strings.Repeat("c", 64))
	if e := s.ApproveUpgradeImages(ctx, step); e == nil {
		t.Fatal("concurrent registry policy overwritten")
	}
	insert(old)
	if e := s.ApproveUpgradeImages(ctx, step); e != nil {
		t.Fatal(e)
	}
	var before, after []byte
	if e := p.QueryRow(ctx, `SELECT registration FROM deployment_nodes WHERE id=$1`, id).Scan(&before); e != nil {
		t.Fatal(e)
	}
	if e := s.VerifyUpgradeImages(ctx, step); e != nil {
		t.Fatal(e)
	}
	if e := p.QueryRow(ctx, `SELECT registration FROM deployment_nodes WHERE id=$1`, id).Scan(&after); e != nil || !bytes.Equal(before, after) {
		t.Fatal("verification mutated policy", e)
	}
}
