package queryipc

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/lifecycle"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type blocked struct {
	started  chan struct{}
	finished chan struct{}
}

func (b blocked) Execute(ctx context.Context, _ query.Filter, _ []domain.Object) ([]domain.QueryRow, error) {
	close(b.started)
	<-ctx.Done()
	close(b.finished)
	return nil, ctx.Err()
}
func TestSocketIsolationBodyWhitelistAndCancel(t *testing.T) {
	dir, e := os.MkdirTemp("", "q-")
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "query.sock")
	state := lifecycle.New(time.Now)
	ctx, stop := context.WithCancel(lifecycle.WithState(t.Context(), state))
	defer stop()
	b := blocked{make(chan struct{}), make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, socket, b) }()
	// Listen creates the inode before Serve applies its private mode. The
	// runtime readiness signal is published after chmod, so observing only
	// existence can race initialization and falsely report insecure access.
	for i := 0; i < 100; i++ {
		if state.Ready(lifecycle.Query) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !state.Ready(lifecycle.Query) {
		t.Fatal("query socket initialization did not become ready")
	}
	st, e := os.Stat(socket)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatal("socket permissions", e)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: time.Second}
	r, e := client.Post("http://query/execute", "application/json", strings.NewReader(`{"SQL":"INSTALL evil"}`))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 400 {
		t.Fatal("SQL accepted")
	}
	requestCtx, cancel := context.WithCancel(t.Context())
	requestDone := make(chan error, 1)
	go func() {
		_, e := NewClient(socket).Execute(requestCtx, query.Filter{SiteIDs: []string{"11111111-1111-4111-8111-111111111111"}, From: time.Now(), To: time.Now().Add(time.Hour)}, nil)
		requestDone <- e
	}()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("execution not started")
	}
	cancel()
	select {
	case <-b.finished:
	case <-time.After(time.Second):
		t.Fatal("HTTP cancel failed to reach executor")
	}
	if e = <-requestDone; !errors.Is(e, ErrUnavailable) {
		t.Fatal(e)
	}
	stop()
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}

func TestQueryDrainRefusesNewWorkAndCancelsExistingAtDeadline(t *testing.T) {
	dir, e := os.MkdirTemp("", "qd-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "query.sock")
	state := lifecycle.New(time.Now)
	ctx, cancel := context.WithTimeout(lifecycle.WithState(t.Context(), state), 500*time.Millisecond)
	defer cancel()
	engine := blocked{started: make(chan struct{}), finished: make(chan struct{})}
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, socket, engine) }()
	until := time.NewTimer(time.Second)
	defer until.Stop()
	for !state.Ready(lifecycle.Query) {
		select {
		case <-until.C:
			t.Fatal("query did not become ready")
		case <-time.After(5 * time.Millisecond):
		}
	}
	client := NewClient(socket)
	filter := query.Filter{SiteIDs: []string{"11111111-1111-4111-8111-111111111111"}, From: time.Now(), To: time.Now().Add(time.Hour)}
	requestDone := make(chan struct{})
	go func() { _, _ = client.Execute(t.Context(), filter, nil); close(requestDone) }()
	select {
	case <-engine.started:
	case <-time.After(time.Second):
		t.Fatal("existing query did not start")
	}
	deadline, _ := ctx.Deadline()
	state.BeginDrain(deadline)
	if _, e = NewClient(socket).Execute(t.Context(), filter, nil); !errors.Is(e, ErrUnavailable) {
		t.Fatal("new query admitted during drain", e)
	}
	select {
	case <-engine.finished:
		t.Fatal("existing query cancelled before deadline")
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case <-engine.finished:
	case <-time.After(time.Second):
		t.Fatal("query deadline did not cancel engine")
	}
	select {
	case <-requestDone:
	case <-time.After(time.Second):
		t.Fatal("query connection did not close")
	}
	if e = <-done; e != nil {
		t.Fatal(e)
	}
}
