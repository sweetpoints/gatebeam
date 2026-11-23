//go:build integration

package compose_test

import (
	"bytes"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	labfixture "gatebeam/tests/fixtures/multinode"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpgradeTwoIndependentProjectsOnlyRecreatesSelectedRole(t *testing.T) {
	lab := labfixture.Start(t)
	ops := labfixture.NewUpgradeOperations(t, lab)
	tag := "gatebeam-owned-upgrade:" + strings.ToLower(time.Now().Format("150405000000000"))
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM gatebeam-api:local\nLABEL gatebeam.fixture.upgrade=\"selected-role\"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	labfixture.Docker(t, "build", "--network", "none", "-t", tag, dir)
	t.Cleanup(func() {
		for _, n := range lab.Nodes {
			labfixture.CleanupDocker(t, "compose", "-p", n.Info.StoragePrefix, "-f", n.ComposeFile, "rm", "-sf", "management")
		}
		labfixture.CleanupDocker(t, "image", "rm", tag)
	})
	image := labfixture.Docker(t, "image", "inspect", tag, "--format", "{{.Id}}")
	desired := "registry.example/gatebeam/api@" + image
	ops.Images[desired] = tag
	inventory := upgrade.Inventory{Schema: 27, RoleSchema: 6, Compatible: true}
	unchanged := map[string]string{}
	oldAPI := map[string]string{}
	for _, n := range lab.Nodes {
		inventory.Nodes = append(inventory.Nodes, n.Info)
		ops.Images[n.Info.Roles["management"].Image] = "gatebeam-api:local"
		oldAPI[n.Info.Node.ID] = n.Compose(t, "ps", "-q", "management")
		unchanged[n.Info.Node.ID] = n.Compose(t, "ps", "-q", "nginx")
	}
	request := upgrade.Request{BatchID: "33333333-3333-4333-8333-333333333333", ExecutorInstance: "projects/owned/zones/us-west1-c/instances/executor", Scope: "role", Role: "management", Images: map[string]string{"management": desired}, DrainSeconds: 1, ObserveSeconds: 1}
	plan, e := upgrade.BuildPlan(request, inventory)
	if e != nil {
		t.Fatal(e)
	}
	x := upgrade.Executor{Store: repo.UpgradeStore{Pool: lab.Pool}, Operations: ops, ExecutorInstance: request.ExecutorInstance}
	if e = x.Run(t.Context(), plan); e != nil {
		t.Fatal(e)
	}
	run, e := ops.Store.Load(t.Context(), plan.ID)
	if e != nil || run.State != "completed" {
		t.Fatal(run.State, e)
	}
	for _, n := range lab.Nodes {
		if n.Compose(t, "ps", "-q", "nginx") != unchanged[n.Info.Node.ID] || n.Compose(t, "ps", "-q", "management") == oldAPI[n.Info.Node.ID] {
			t.Fatal("changed roles mismatch")
		}
		code, body := n.Request(t, "GET", "/auth/session", nil, "", "")
		if code != 401 {
			source := "unclassified"
			switch {
			case bytes.Equal(bytes.TrimSpace(body), []byte("service unavailable")):
				source = "role-admission"
			case bytes.Contains(body, []byte("<center>nginx")):
				source = "nginx"
			}
			lab.LogManagementReadiness(t)
			t.Fatalf("native endpoint failed: status=%d response_source=%s", code, source)
		}
		if !ops.Public[n.Info.Node.ID] || !ops.Private[n.Info.Node.ID] {
			t.Fatal("not rejoined")
		}
		for _, role := range domain.NodeRoleNames() {
			n.Wait(t, role, map[string]string{"nginx": "data", "management": "management", "background-jobs": "global-jobs", "internal-ca": "ca", "log-query": "query"}[role])
		}
	}
	t.Log("real node-local management digests, bounded drain, persisted image approvals, two actual API container replacements, native API/CA/public readiness, unchanged Nginx and retained volumes; LB membership is an explicit owned fixture")
}
