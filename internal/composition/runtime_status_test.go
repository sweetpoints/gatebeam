package composition

import (
	"context"
	"encoding/json"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRuntimeOverviewShowsIndependentPeerMaintenance(t *testing.T) {
	data := lifecycle.New(time.Now)
	data.SetReady(lifecycle.Data, true)
	management := lifecycle.New(time.Now)
	management.SetReady(lifecycle.Management, true)
	management.SetMaintenance(true)
	serve := func(s *lifecycle.State) *httptest.Server {
		server := httptest.NewServer(healthHandler(s))
		t.Cleanup(server.Close)
		return server
	}
	dataServer, managementServer := serve(data), serve(management)
	cfg := bootstrap.Config{HealthEndpoints: map[string]map[string]string{"node-a": {"nginx": dataServer.URL + "/status", "management": managementServer.URL + "/status"}, "node-b": {"log-query": "http://127.0.0.1:1/status"}}}
	overview := readRuntimeOverview(context.Background(), cfg)
	if len(overview.Nodes) != 2 || !overview.Nodes[0].Roles[0].Available || !overview.Nodes[0].Roles[0].Status.Ready[lifecycle.Data] || overview.Nodes[0].Roles[1].Status.Mode != "maintenance" || overview.Nodes[1].Roles[0].Available {
		body, _ := json.Marshal(overview)
		t.Fatalf("independent role state hidden: %s", body)
	}
	cfg.HealthEndpoints = map[string]map[string]string{"node-a": {"management": "http://example.com/status"}}
	if overview = readRuntimeOverview(context.Background(), cfg); overview.Nodes[0].Roles[0].Available {
		t.Fatal("public health destination accepted")
	}
}
