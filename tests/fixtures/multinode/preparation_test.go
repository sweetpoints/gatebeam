//go:build integration

package multinode

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

type preparationTransport func(*http.Request) (*http.Response, error)

func (f preparationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestInitialAPISetupDoesNotChangeFunctionalClientDeadline(t *testing.T) {
	t.Setenv("GATEBEAM_ACCEPTANCE_EXECUTION", "software-emulated-vm")
	synctest.Test(t, func(t *testing.T) {
		client := &http.Client{Timeout: 30 * time.Millisecond, Transport: preparationTransport(func(r *http.Request) (*http.Response, error) {
			if r.Host != "management.dual.test" || r.URL.Path != "/certificates/spec" || r.Header.Get("X-CSRF-Token") != "owned-csrf" {
				return nil, errors.New("fixture request identity changed")
			}
			timer := time.NewTimer(60 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-r.Context().Done():
				return nil, r.Context().Err()
			case <-timer.C:
			}
			return &http.Response{StatusCode: 201, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("owned-created")), Request: r}, nil
		})}
		node := &Node{PublicClient: client}
		session := &Session{Cookie: "owned-cookie", CSRF: "owned-csrf", Lab: &Lab{Nodes: []*Node{node}}}
		raw := session.prepareCall(t, "POST", "/certificates/spec", map[string]string{"name": "owned"}, 201)
		if string(raw) != "owned-created" {
			t.Fatal("initial setup did not complete")
		}
		if node.PublicClient != client || client.Timeout != 30*time.Millisecond {
			t.Fatal("preparation mutated the functional client")
		}
		req, err := http.NewRequest("POST", "https://management.dual.test/certificates/spec", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("X-CSRF-Token", "owned-csrf")
		if _, err := client.Do(req); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("ordinary functional request lost its original deadline", err)
		}
	})
}

func TestCleanupCommandsDoNotShareSpentDeadline(t *testing.T) {
	t.Setenv("GATEBEAM_ACCEPTANCE_EXECUTION", "native")
	synctest.Test(t, func(t *testing.T) {
		// Two node removals plus image removal may jointly exceed one command's
		// guard while each owned operation is independently within its deadline.
		for range 3 {
			var command context.Context
			err := cleanupCommand(func(ctx context.Context) error {
				command = ctx
				time.Sleep(15 * time.Second)
				return ctx.Err()
			})
			if err != nil {
				t.Fatal("previous cleanup spent the next command's budget", err)
			}
			if command.Err() != context.Canceled {
				t.Fatal("completed cleanup retained its context")
			}
		}
		if err := cleanupCommand(func(ctx context.Context) error {
			time.Sleep(21 * time.Second)
			return ctx.Err()
		}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("stalled cleanup lost its finite guard", err)
		}
		if err := cleanupCommand(func(ctx context.Context) error { return ctx.Err() }); err != nil {
			t.Fatal("failed cleanup poisoned the following operation", err)
		}
	})
}
