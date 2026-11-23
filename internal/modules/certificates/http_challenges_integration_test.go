//go:build integration

package certificates_test

import (
	"context"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/httpchallenge"
	repo "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

type challengeNodes struct{ targets []app.NodeRef }

func (a *challengeNodes) TargetsWithin(transaction.Scope) ([]app.NodeRef, error) {
	return append([]app.NodeRef{}, a.targets...), nil
}
func (a *challengeNodes) CallerWithin(_ transaction.Scope, n app.NodeRef) error {
	for _, ref := range a.targets {
		if ref == n {
			return nil
		}
	}
	return app.ErrChallenge
}
func TestHTTP01ReadyOnEveryServingNode(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	nodes := &challengeNodes{[]app.NodeRef{{ID: uuid.NewString(), Epoch: 1}, {ID: uuid.NewString(), Epoch: 1}}}
	service := app.NewHTTPChallenges(postgres.NewRunner(p), repo.NewHTTPChallenges(), nodes)
	owner := uuid.NewString()
	token := "standard_acme_token"
	keyAuth := token + ".account_thumbprint"
	if e := service.Prepare(ctx, owner, token, keyAuth, nodes.targets); e != nil {
		t.Fatal(e)
	}
	dirs := []string{t.TempDir(), t.TempDir()}
	for i, dir := range dirs {
		resolved, e := filepath.EvalSymlinks(dir)
		if e != nil {
			t.Fatal(e)
		}
		dirs[i] = resolved
	}
	servers := []*httptest.Server{}
	for _, dir := range dirs {
		s := httptest.NewServer(http.FileServer(http.Dir(dir)))
		defer s.Close()
		servers = append(servers, s)
	}
	syncNode := func(i int) {
		t.Helper()
		local, e := httpchallenge.New(dirs[i])
		if e != nil {
			t.Fatal(e)
		}
		if e = service.Sync(ctx, nodes.targets[i], local); e != nil {
			t.Fatal(e)
		}
	}
	if ready, e := service.Ready(ctx, owner); e != nil || ready {
		t.Fatalf("ready before preparation: %v %v", ready, e)
	}
	syncNode(0)
	if ready, e := service.Ready(ctx, owner); e != nil || ready {
		t.Fatalf("ready with only A: %v %v", ready, e)
	}
	syncNode(1)
	if ready, e := service.Ready(ctx, owner); e != nil || !ready {
		t.Fatalf("both not ready: %v %v", ready, e)
	}
	// A fresh local adapter has no memory of a previous process. Recreate the
	// webroot file, then recover from the durable challenge ledger.
	if e := os.Remove(filepath.Join(dirs[1], ".well-known/acme-challenge", token)); e != nil {
		t.Fatal(e)
	}
	syncNode(1)
	for i := 0; i < 12; i++ {
		r, e := http.Get(servers[i%2].URL + "/.well-known/acme-challenge/" + token)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(r.Body)
		r.Body.Close()
		if e != nil || r.StatusCode != 200 || string(b) != keyAuth {
			t.Fatalf("standard HTTP01 on node %d: %s %v", i%2, b, e)
		}
	}
	// New serving membership invalidates the old all-node acknowledgement.
	nodes.targets = append(nodes.targets, app.NodeRef{ID: uuid.NewString(), Epoch: 1})
	if ready, e := service.Ready(ctx, owner); e != nil || ready {
		t.Fatalf("membership changed but still ready: %v %v", ready, e)
	}
	nodes.targets = nodes.targets[:2]
	if e := service.Cleanup(ctx, owner); e != nil {
		t.Fatal(e)
	}
	syncNode(0)
	syncNode(1)
	for _, dir := range dirs {
		if _, e := os.Stat(filepath.Join(dir, ".well-known/acme-challenge", token)); !os.IsNotExist(e) {
			t.Fatalf("owned token remains: %v", e)
		}
	}
	if e := service.Prepare(ctx, uuid.NewString(), "../escape", "bad", nodes.targets); e == nil {
		t.Fatal("path traversal accepted")
	}
}
