package composition

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/lifecycle"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
)

type activationTransport func(*http.Request) (*http.Response, error)

func (f activationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestActivationRefusesOneUnreadyRole(t *testing.T) {
	pair := []domain.NodeDeployment{}
	for _, name := range []string{"a", "b"} {
		raw, e := os.ReadFile("../../deploy/nodes/" + name + ".example.json")
		if e != nil {
			t.Fatal(e)
		}
		raw = []byte(strings.ReplaceAll(strings.ReplaceAll(string(raw), "projects/REPLACE/", "projects/owned/"), "REPLACE_64_HEX", strings.Repeat("a", 64)))
		var n domain.NodeDeployment
		if e = json.Unmarshal(raw, &n); e != nil {
			t.Fatal(e)
		}
		pair = append(pair, n)
	}
	healthy := false
	calls := 0
	client := &http.Client{Transport: activationTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		state := lifecycle.Snapshot{Live: true, Mode: "serving", Ready: map[string]bool{lifecycle.Data: true, lifecycle.Management: true, lifecycle.GlobalJobs: true, lifecycle.LocalCleanup: true, lifecycle.Query: true, lifecycle.ACME: true, lifecycle.Status: true}, Details: map[string]string{"artifact_id": strings.Repeat("a", 64), "generation": "initial"}}
		if !healthy && r.URL.Host == "10.42.0.31:19094" {
			state.Ready[lifecycle.Status] = false
		}
		raw, _ := json.Marshal(state)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
	})}
	if _, e := activationProbes(context.Background(), pair, client); e == nil {
		t.Fatal("one broken CA status capability allowed activation")
	}
	healthy = true
	proof, e := activationProbes(context.Background(), pair, client)
	if e != nil || len(proof) != 2 || calls < 10 {
		t.Fatal("complete cohort not probed", len(proof), calls, e)
	}
}

func TestActivationRejectsDeclaredImageWithoutHostMatch(t *testing.T) {
	n := domain.NodeDeployment{Roles: map[string]domain.RoleDeployment{"management": {Image: "registry.test/api@sha256:" + strings.Repeat("a", 64)}}}
	if activationImages(n, map[string]string{"management": "registry.test/api@sha256:" + strings.Repeat("b", 64)}) == nil {
		t.Fatal("inventory declaration was accepted as actual host image")
	}
	if e := activationImages(n, map[string]string{"management": n.Roles["management"].Image}); e != nil {
		t.Fatal(e)
	}
}
