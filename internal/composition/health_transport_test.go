package composition

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOwnerTransportPreservesFiveSecondWorkAndRejectsExpiry(t *testing.T) {
	for _, exhausted := range []bool{false, true} {
		name := "work_within_budget"
		if exhausted {
			name = "work_budget_exhausted"
		}
		t.Run(name, func(t *testing.T) {
			var expired atomic.Bool
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				defer cancel()
				if exhausted {
					<-ctx.Done()
					expired.Store(true)
					http.Error(w, "capability unavailable", http.StatusServiceUnavailable)
					return
				}
				select {
				case <-time.After(3500 * time.Millisecond):
					w.WriteHeader(http.StatusNoContent)
				case <-ctx.Done():
					http.Error(w, "capability unavailable", http.StatusServiceUnavailable)
				}
			})
			socket := filepath.Join(ownerTransportDirectory(t), "owner.sock")
			listener, err := net.Listen("unix", socket)
			if err != nil {
				t.Fatal(err)
			}
			server := roleHTTPServer(handler, true)
			defer server.Close()
			go func() { _ = server.Serve(listener) }()
			transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
			response, err := client.Post("http://owner/capabilities/verify", "application/json", nil)
			if err != nil {
				t.Fatal("bounded owner response lost", err)
			}
			defer response.Body.Close()
			want := http.StatusNoContent
			if exhausted {
				want = http.StatusServiceUnavailable
			}
			if response.StatusCode != want || expired.Load() != exhausted {
				t.Fatal("owner response changed the work budget", response.StatusCode, expired.Load())
			}
		})
	}
}

func TestRoleListenersKeepDistinctResponseBudgets(t *testing.T) {
	directory := ownerTransportDirectory(t)
	health, err := startRoleHealth(t.Context(), bootstrap.Config{HealthListen: "127.0.0.1:0", ControlSocket: filepath.Join(directory, "control.sock")}, lifecycle.New(time.Now))
	if err != nil {
		t.Fatal(err)
	}
	defer health.Close()
	if len(health.servers) != 2 || health.servers[0].WriteTimeout != 3*time.Second || health.servers[1].WriteTimeout != 8*time.Second {
		t.Fatal("health and owner response policies were mixed")
	}
	info, err := os.Stat(health.socket)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("owner socket is not private", err)
	}
	for _, server := range health.servers {
		if server.ReadHeaderTimeout != 2*time.Second || server.ReadTimeout != 3*time.Second || server.IdleTimeout != 5*time.Second {
			t.Fatal("unrelated request deadlines changed")
		}
	}
}

func ownerTransportDirectory(t *testing.T) string {
	t.Helper()
	// Test names can exceed sockaddr_un's path limit under a long CI TMPDIR.
	directory, err := os.MkdirTemp("", "gb-own-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	canonical, err := filepath.EvalSymlinks(directory)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
