//go:build integration

package multinode

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/deployment/application/upgrade"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/lifecycle"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestRouterPortCacheRefreshAfterTopologyChange(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(lifecycle.Snapshot{Live: true, Mode: "serving", Ready: map[string]bool{lifecycle.Data: true}})
	})
	old := httptest.NewServer(handler)
	t.Cleanup(old.Close)
	directory := t.TempDir()
	metadata := filepath.Join(directory, "published-address")
	if err := os.WriteFile(metadata, []byte(old.Listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "docker"), []byte("#!/bin/sh\ncat \"$GATEBEAM_TEST_PUBLISHED_ADDRESS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GATEBEAM_TEST_PUBLISHED_ADDRESS", metadata)
	node := &Node{Router: "owned-router"}
	if state, err := node.ProbeHealth(t, "nginx"); err != nil || !state.Ready[lifecycle.Data] {
		t.Fatal("initial actual HTTP endpoint unavailable")
	}
	current := httptest.NewServer(handler)
	t.Cleanup(current.Close)
	old.Close()
	if err := os.WriteFile(metadata, []byte(current.Listener.Addr().String()), 0600); err != nil {
		t.Fatal(err)
	}
	node.RefreshPorts(t)
	if err := os.Remove(metadata); err != nil {
		t.Fatal(err)
	}
	if state, err := node.ProbeHealth(t, "nginx"); err != nil || !state.Ready[lifecycle.Data] {
		t.Fatal("topology refresh still probed the removed HTTP endpoint", err)
	}
}

// A stable router's published addresses are fixture preparation. Re-running
// slow Docker metadata commands must not consume the bounded HTTP readiness
// window after a role restart. The role is genuinely unready for its first
// probe, then serves real healthy HTTP responses and the CA directory.
func TestUpgradeReadinessDoesNotSpendItsWindowRediscoveringRouterPorts(t *testing.T) {
	var armed atomic.Bool
	var probes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/acme/server/directory" {
			w.Write([]byte(`{}`))
			return
		}
		healthy := !armed.Load() || probes.Add(1) > 1
		json.NewEncoder(w).Encode(lifecycle.Snapshot{Live: true, Mode: "serving", Ready: map[string]bool{"data": healthy, "management": healthy, "global-jobs": healthy, "local-cleanup": healthy, "acme": healthy, "status": healthy, "query": healthy}})
	}))
	defer server.Close()
	dir := t.TempDir()
	marker := filepath.Join(dir, "slow")
	script := "#!/bin/sh\nif test -f '" + marker + "'; then /bin/sleep 1.1; fi\nprintf '%s\\n' '" + server.Listener.Addr().String() + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	node := &Node{Router: "owned-stable-router", Info: domain.NodeDeployment{Node: domain.NodeRef{ID: "owned-node"}}}
	ca := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer ca.Close()
	transport := ca.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "127.0.0.1"
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ca.Listener.Addr().String())
	}
	node.CAClient = &http.Client{Timeout: time.Second, Transport: transport}
	defer node.CAClient.CloseIdleConnections()
	step := upgrade.Step{ID: "verify-owned", Kind: "verify-private", Node: node.Info.Node}
	ops := &UpgradeOperations{T: t, Lab: &Lab{Nodes: []*Node{node}}, Calls: []upgrade.Step{step}}
	if state, err := ops.Observe(t.Context(), node.Info.Node.ID); err != nil || !state.Ready {
		t.Fatal("initial owned HTTP services not ready")
	}
	if err := os.WriteFile(marker, []byte("slow metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	armed.Store(true)
	start := time.Now()
	if err := ops.Wait(t.Context(), upgrade.OperationRef{StepID: step.ID}); err != nil {
		t.Fatalf("healthy role rejected after metadata exhausted its HTTP window: %v", err)
	}
	if elapsed := time.Since(start); elapsed >= 5*time.Second {
		t.Fatalf("router metadata rediscovery delayed healthy HTTP verification: %s", elapsed)
	}
	if probes.Load() < 6 {
		t.Fatal("verification did not retry the initially unready real HTTP service")
	}
}

// A role restart can briefly accept TCP before its HTTP listener is ready.
// The existing caller's bounded loop needs a transport error, not a fatal test
// exit or a fabricated not-ready snapshot, before it can verify the real state.
func TestHealthProbeReturnsRestartEOFThenActualUnreadyState(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			conn.Close()
			return
		}
		json.NewEncoder(w).Encode(lifecycle.Snapshot{Live: true, Mode: "serving", Ready: map[string]bool{"global-jobs": false}})
	}))
	defer server.Close()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\nprintf '%s\\n' '"+server.Listener.Addr().String()+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	node := &Node{Router: "owned-restarting-router"}
	if _, err := node.ProbeHealth(t, "background-jobs"); err == nil {
		t.Fatal("restart EOF was accepted as observed readiness")
	}
	state, err := node.ProbeHealth(t, "background-jobs")
	if err != nil || !state.Live || state.Mode != "serving" || state.Ready["global-jobs"] {
		t.Fatalf("actual role state unavailable after retry: state=%+v error=%v", state, err)
	}
}
