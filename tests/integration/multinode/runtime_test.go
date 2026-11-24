//go:build integration

package multinode_test

import (
	fixture "gatebeam/tests/fixtures/multinode"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if fixture.ProcessMain() {
		return
	}
	os.Exit(m.Run())
}
func TestBothNodesColdStartWithAllControlDependenciesStopped(t *testing.T) {
	lab := fixture.Start(t)
	site := lab.Business(t)
	for _, n := range lab.Nodes {
		if code := site.Get(t, n, "/"); code != 200 {
			t.Fatal("initial business", code)
		}
	}
	db := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	if db == "" {
		t.Fatal("owned database required")
	}
	for _, n := range lab.Nodes {
		n.Compose(t, "stop", "--timeout", "2", "management", "background-jobs", "log-query")
	}
	fixture.Docker(t, "stop", "--time", "2", lab.CAContainer)
	fixture.Docker(t, "network", "disconnect", lab.Network, db)
	for _, n := range lab.Nodes {
		before := n.Compose(t, "ps", "-q", "nginx")
		n.Compose(t, "rm", "-sf", "nginx")
		n.Compose(t, "up", "-d", "--no-build", "--no-deps", "nginx")
		n.Wait(t, "nginx", "data")
		if before == n.Compose(t, "ps", "-q", "nginx") {
			t.Fatal("not a cold container")
		}
		if code := site.Get(t, n, "/"); code != 200 {
			t.Fatal("offline business request", code)
		}
	}
	fixture.Docker(t, "network", "connect", "--alias", "database", lab.Network, db)
	lab.RestartCA(t)
	for _, n := range lab.Nodes {
		n.Compose(t, "start", "management", "background-jobs", "log-query")
		n.Wait(t, "management", "management")
		if code := site.Get(t, n, "/"); code != 200 {
			t.Fatal("reconcile interrupted business", code)
		}
	}
	t.Log("both native Nginx containers destroyed/recreated against retained confirmed storage with PG link isolated and API/jobs/query/CA stopped; this is not a GCP kernel-reboot acceptance")
}
