//go:build integration

package multinode_test

import (
	"encoding/json"
	"gatebeam/internal/integration/certificatematerials"
	"gatebeam/internal/modules/certificates"
	"gatebeam/internal/modules/deployment"
	fixture "gatebeam/tests/fixtures/multinode"
	"github.com/google/uuid"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestDualControlFailuresAndQueryCoverage(t *testing.T) {
	lab := fixture.Start(t)
	business := lab.Business(t)
	session := business.Session
	challenges := certificates.NewHTTPChallenges(lab.Pool, certificatematerials.ChallengeNodes{Nodes: deployment.NewNodes()})
	owner := uuid.NewString()
	token, keyAuth := "ownedchallenge", "ownedchallenge.ownedthumbprint"
	a, b := lab.Nodes[0], lab.Nodes[1]
	a.Compose(t, "stop", "--timeout", "2", "nginx")
	if e := challenges.PrepareCurrent(t.Context(), owner, token, keyAuth); e != nil {
		t.Fatal(e)
	}
	if ok, e := challenges.Ready(t.Context(), owner); e != nil || ok {
		t.Fatal("missing node advertised HTTP01 ready", e)
	}
	a.Compose(t, "start", "nginx")
	a.Wait(t, "nginx", "data")
	deadline := time.Now().Add(6 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		ok, e := challenges.Ready(t.Context(), owner)
		if e == nil && ok {
			ready = true
			break
		}
		time.Sleep(40 * time.Millisecond)
	}
	if !ready {
		t.Fatal("both native token files were not acknowledged")
	}
	for j := 0; j < 12; j++ {
		n := lab.Nodes[(j*7+3)%2]
		req, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+n.Port(t, 80)+"/.well-known/acme-challenge/"+token, nil)
		req.Host = "service.dual.test"
		r, e := http.DefaultClient.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != 200 || string(body) != keyAuth {
			t.Fatal("random entry challenge mismatch", r.StatusCode)
		}
	}
	if e := challenges.Cleanup(t.Context(), owner); e != nil {
		t.Fatal(e)
	}
	for j := 0; j < 40; j++ {
		if business.Get(t, lab.Nodes[j%2], "/") != 200 {
			t.Fatal("business failed")
		}
	}
	time.Sleep(1500 * time.Millisecond)
	page := business.Query(t, "local")
	if page.Job.State != "succeeded" || page.Job.Coverage != "local_complete" {
		t.Fatal("healthy local coverage", page.Job)
	}
	b.Compose(t, "stop", "--timeout", "2", "log-query")
	page = business.Query(t, "local")
	if page.Job.State != "succeeded" || page.Job.Coverage != "local_incomplete" {
		t.Fatal("unavailable node looked complete", page.Job)
	}
	if business.Get(t, b, "/") != 200 {
		t.Fatal("query failure stopped data")
	}
	b.Compose(t, "start", "log-query")
	b.Wait(t, "log-query", "query")
	archive := lab.EnableArchive(t)
	archive.WaitBoth(t)
	a.Compose(t, "stop", "--timeout", "2", "background-jobs", "internal-ca")
	page = business.Query(t, "archive")
	if page.Job.State != "succeeded" || len(page.Rows) == 0 {
		t.Fatal("surviving worker did not query actual archived objects", page.Job)
	}
	found := map[string]bool{}
	for _, row := range page.Rows {
		found[row.NodeID] = true
	}
	for _, n := range lab.Nodes {
		if !found[n.Info.Node.ID] {
			t.Fatal("archive lost node provenance", found)
		}
	}
	archive.DisconnectReaders(t)
	page = business.Query(t, "archive")
	if page.Job.State != "failed" {
		t.Fatal("R2 outage appeared as successful empty history", page.Job)
	}
	r, e := b.CAClient.Get("https://ca.dual.test:8444/acme/server/directory")
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("surviving CA unavailable")
	}
	if _, e = lab.Pool.Exec(t.Context(), `UPDATE identity_accounts SET state='disabled',auth_version=auth_version+1 WHERE id=$1`, session.UserID); e != nil {
		t.Fatal(e)
	}
	for _, n := range lab.Nodes {
		code, raw := n.Request(t, "GET", "/auth/session", nil, session.Cookie, session.CSRF)
		if code != 401 {
			var v any
			json.Unmarshal(raw, &v)
			t.Fatal("revoked principal accepted", code, v)
		}
	}
	t.Log("native random-entry HTTP01 readiness, actual both-node local and S3/DuckDB history, explicit partial coverage, R2 failure, B global query worker/CA and cross-node principal revocation")
}
