package nginx

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type injectedProc struct {
	root                           string
	readFault, linkFault, dirFault map[string]error
}

func (p injectedProc) path(path string) string {
	return filepath.Join(p.root, strings.TrimPrefix(path, "/proc/"))
}
func (p injectedProc) ReadFile(path string) ([]byte, error) {
	if e := p.readFault[path]; e != nil {
		return nil, e
	}
	return os.ReadFile(p.path(path))
}
func (p injectedProc) ReadDir(path string) ([]os.DirEntry, error) {
	if e := p.dirFault[path]; e != nil {
		return nil, e
	}
	return os.ReadDir(p.path(path))
}
func (p injectedProc) Readlink(path string) (string, error) {
	if e := p.linkFault[path]; e != nil {
		return "", e
	}
	return os.Readlink(p.path(path))
}
func (p injectedProc) Lstat(path string) (os.FileInfo, error) { return os.Lstat(p.path(path)) }
func procFixture(t *testing.T) injectedProc {
	t.Helper()
	p := injectedProc{root: t.TempDir(), readFault: map[string]error{}, linkFault: map[string]error{}, dirFault: map[string]error{}}
	for _, dir := range []string{"net", "42/fd"} {
		if e := os.MkdirAll(filepath.Join(p.root, dir), 0700); e != nil {
			t.Fatal(e)
		}
	}
	for _, file := range []string{"tcp", "tcp6"} {
		if e := os.WriteFile(filepath.Join(p.root, "net", file), []byte("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n0: 0100007F:2382 00000000:0000 0A 0:0 00:0 0 101 0 123\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	if e := os.Symlink("socket:[123]", filepath.Join(p.root, "42/fd/3")); e != nil {
		t.Fatal(e)
	}
	return p
}
func TestListenerInspectionFailsClosedOnUnknownProcState(t *testing.T) {
	for _, kind := range []string{"tcp-denied", "tcp6-io", "tcp6-missing", "fd-denied", "fd-missing-but-live", "worker-fd-missing-but-live", "malformed-table"} {
		t.Run(kind, func(t *testing.T) {
			fs := procFixture(t)
			switch kind {
			case "tcp-denied":
				fs.readFault["/proc/net/tcp"] = os.ErrPermission
			case "tcp6-io":
				fs.readFault["/proc/net/tcp6"] = errors.New("I/O failure")
			case "tcp6-missing":
				fs.readFault["/proc/net/tcp6"] = os.ErrNotExist
			case "fd-denied":
				fs.linkFault["/proc/42/fd/3"] = os.ErrPermission
			case "fd-missing-but-live":
				fs.linkFault["/proc/42/fd/3"] = os.ErrNotExist
			case "worker-fd-missing-but-live":
				fs.dirFault["/proc/42/fd"] = os.ErrNotExist
			case "malformed-table":
				if e := os.WriteFile(fs.path("/proc/net/tcp"), []byte("truncated"), 0600); e != nil {
					t.Fatal(e)
				}
			}
			p := Process{proc: fs}
			retired, e := p.retiredListeners(map[string]bool{"42": true})
			if e == nil || retired {
				t.Fatalf("unknown listener state acknowledged: retired=%v error=%v", retired, e)
			}
		})
	}
}
func TestListenerInspectionAcceptsOnlyObservedRetirement(t *testing.T) {
	fs := procFixture(t)
	p := Process{proc: fs}
	if retired, e := p.retiredListeners(map[string]bool{"42": true}); e != nil || retired {
		t.Fatalf("active listener: %v %v", retired, e)
	}
	if e := os.Remove(fs.path("/proc/42/fd/3")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("socket:[456]", fs.path("/proc/42/fd/3")); e != nil {
		t.Fatal(e)
	}
	if retired, e := p.retiredListeners(map[string]bool{"42": true}); e != nil || !retired {
		t.Fatalf("established stream mistaken for listener: %v %v", retired, e)
	}
	if e := os.RemoveAll(fs.path("/proc/42")); e != nil {
		t.Fatal(e)
	}
	if retired, e := p.retiredListeners(map[string]bool{"42": true}); e != nil || !retired {
		t.Fatalf("proven exited worker: %v %v", retired, e)
	}
}

type changingProc struct {
	injectedProc
	calls      int
	persistent bool
}

func (p *changingProc) ReadFile(path string) ([]byte, error) {
	if path == "/proc/net/tcp" {
		p.calls++
		if p.persistent || p.calls == 1 {
			return nil, os.ErrPermission
		}
	}
	return p.injectedProc.ReadFile(path)
}

type generationProbe struct {
	cancel context.CancelFunc
	proc   *changingProc
	calls  int
	t      *testing.T
}

func (p *generationProbe) RoundTrip(r *http.Request) (*http.Response, error) {
	p.calls++
	if p.proc.calls < 2 {
		p.t.Error("version queried before conclusive listener observation")
	}
	if p.cancel != nil {
		p.cancel()
	}
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("new/g2")), Header: http.Header{}}, nil
}
func generationFixture(t *testing.T, persistent bool) (*Process, *changingProc, *generationProbe) {
	fs := procFixture(t)
	if e := os.MkdirAll(fs.path("/proc/42/task/42"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(fs.path("/proc/42/task/42/children"), []byte("43"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(fs.path("/proc/42/fd/3")); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("socket:[456]", fs.path("/proc/42/fd/3")); e != nil {
		t.Fatal(e)
	}
	proc := &changingProc{injectedProc: fs, persistent: persistent}
	probe := &generationProbe{proc: proc, t: t}
	return &Process{proc: proc, cmd: &exec.Cmd{Process: &os.Process{Pid: 42}}, done: make(chan struct{}), probe: &http.Client{Transport: probe}}, proc, probe
}
func TestGenerationWaitRetriesUnknownWithoutAcknowledging(t *testing.T) {
	p, proc, probe := generationFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if e := p.waitGeneration(ctx, map[string]bool{"42": true}, "new/g2"); e != nil {
		t.Fatal("transient unknown abandoned", e)
	}
	if proc.calls < 2 || probe.calls != 1 {
		t.Fatal("acknowledged without conclusive fresh worker/listener/version", proc.calls, probe.calls)
	}
}
func TestGenerationWaitPersistentUnknownKeepsCauseAndDeadline(t *testing.T) {
	p, proc, probe := generationFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()
	e := p.waitGeneration(ctx, map[string]bool{"42": true}, "new/g2")
	if !errors.Is(e, context.DeadlineExceeded) || !strings.Contains(e.Error(), "listener observation unavailable") || proc.calls < 2 || probe.calls != 0 {
		t.Fatal("persistent unknown acknowledged or lost authority deadline", e, proc.calls, probe.calls)
	}
}
func TestGenerationWaitCanceledImmediately(t *testing.T) {
	p, proc, probe := generationFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if e := p.waitGeneration(ctx, map[string]bool{"42": true}, "new/g2"); !errors.Is(e, context.Canceled) || proc.calls != 0 || probe.calls != 0 {
		t.Fatal("canceled authority performed observation", e, proc.calls, probe.calls)
	}
}

func TestGenerationWaitDoesNotAcknowledgeCanceledVersionResponse(t *testing.T) {
	p, _, probe := generationFixture(t, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	probe.cancel = cancel
	if e := p.waitGeneration(ctx, map[string]bool{"42": true}, "new/g2"); !errors.Is(e, context.Canceled) {
		t.Fatal("canceled authority acknowledged completed response", e)
	}
}
