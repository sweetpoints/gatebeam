//go:build integration

package composition

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A task-local TCP relay makes the real PostgreSQL unavailable without changing
// any database/container state or unrelated services.
type dbRelay struct {
	net.Listener
	mu     sync.Mutex
	down   bool
	active map[net.Conn]bool
	target string
}

func newRelay(t *testing.T, target string) *dbRelay {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := &dbRelay{Listener: l, active: map[net.Conn]bool{}, target: target}
	go func() {
		for {
			front, e := l.Accept()
			if e != nil {
				return
			}
			p.mu.Lock()
			if p.down {
				p.mu.Unlock()
				front.Close()
				continue
			}
			p.active[front] = true
			p.mu.Unlock()
			go p.copy(front)
		}
	}()
	t.Cleanup(func() { l.Close(); p.setDown(true) })
	return p
}
func (p *dbRelay) copy(front net.Conn) {
	defer func() { front.Close(); p.mu.Lock(); delete(p.active, front); p.mu.Unlock() }()
	back, e := net.DialTimeout("tcp", p.target, time.Second)
	if e != nil {
		return
	}
	defer back.Close()
	done := make(chan struct{})
	go func() { _, _ = io.Copy(back, front); _ = back.Close(); close(done) }()
	_, _ = io.Copy(front, back)
	front.Close()
	<-done
}
func (p *dbRelay) setDown(down bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.down = down
	if down {
		for c := range p.active {
			c.Close()
		}
	}
}
func TestAPIRuntimeDatabaseReadinessRecovers(t *testing.T) {
	dsn := os.Getenv("GATEBEAM_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("run scripts/check-db.sh: PostgreSQL DSN required")
	}
	u, e := url.Parse(dsn)
	if e != nil {
		t.Fatal("test DSN invalid")
	}
	relay := newRelay(t, u.Host)
	u.Host = relay.Addr().String()
	dir := t.TempDir()
	database := filepath.Join(dir, "database")
	if e = os.WriteFile(database, []byte(u.String()), 0600); e != nil {
		t.Fatal(e)
	}
	identity := filepath.Join(dir, "identity")
	if e = secrets.EnsureIdentity(identity); e != nil {
		t.Fatal(e)
	}
	reserve, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := reserve.Addr().String()
	reserve.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, "api", bootstrap.Config{Environment: "development", IdentityFile: identity, DatabaseFile: database, APIListen: address, APIOrigin: "http://" + address})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(6 * time.Second):
			t.Error("API shutdown deadline")
		}
	})
	client := &http.Client{Timeout: 2 * time.Second}
	wait := func(path string, want int) {
		t.Helper()
		deadline := time.Now().Add(8 * time.Second)
		for time.Now().Before(deadline) {
			r, e := client.Get("http://" + address + path)
			if e == nil {
				body, _ := io.ReadAll(r.Body)
				r.Body.Close()
				if strings.Contains(string(body), "postgres") || strings.Contains(string(body), "test-only") {
					t.Fatal("probe disclosed database credentials")
				}
				if r.StatusCode == want {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("%s never became %d", path, want)
	}
	wait("/readyz", 200)
	relay.setDown(true)
	wait("/readyz", 503)
	wait("/livez", 200)
	relay.setDown(false)
	wait("/readyz", 200)
}
