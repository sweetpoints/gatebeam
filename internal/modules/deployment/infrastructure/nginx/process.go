package nginx

import (
	"context"
	"errors"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// Process controls only its direct child with fixed arguments and signals. It
// never adopts arbitrary PID files, accepts shell text, or reaches Docker APIs.
type Process struct {
	binary, root string
	proc         procReader
	mu           sync.Mutex
	cmd          *exec.Cmd
	done         chan struct{}
	probe        *http.Client
}

func NewProcess(binary, root string) (*Process, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("edge supervisor requires a non-root shared process UID")
	}
	if !filepath.IsAbs(binary) || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid native runtime paths")
	}
	return &Process{proc: nativeProc{}, binary: binary, root: root, probe: &http.Client{Timeout: 500 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}}, nil
}
func (p *Process) Validate(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if filepath.Dir(path) != filepath.Join(p.root, "releases") {
		return errors.New("validation artifact outside runtime root")
	}
	// Output can contain certificate paths or user hostnames. Return bounded fixed
	// failure metadata rather than logging arbitrary Nginx diagnostics.
	cmd := exec.CommandContext(ctx, p.binary, "-t", "-p", path+"/", "-c", filepath.Join(path, "nginx.conf"))
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if e := cmd.Run(); e != nil {
		return errors.New("native Nginx validation failed")
	}
	return nil
}
func (p *Process) running() bool {
	if p.cmd == nil {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}
func (p *Process) Activate(ctx context.Context, version string) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p.mu.Lock()
	if e := ctx.Err(); e != nil {
		p.mu.Unlock()
		return e
	}
	previous := map[string]bool{}
	if !p.running() {
		path := filepath.Join(p.root, "current")
		cmd := exec.Command(p.binary, "-p", path+"/", "-c", filepath.Join(path, "nginx.conf"), "-g", "daemon off;")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
		if e := cmd.Start(); e != nil {
			p.mu.Unlock()
			return errors.New("Nginx child start failed")
		}
		p.cmd = cmd
		p.done = make(chan struct{})
		done := p.done
		go func() { _ = cmd.Wait(); close(done) }()
	} else {
		var e error
		previous, e = p.workers()
		if e != nil {
			p.mu.Unlock()
			return e
		}
		if e := ctx.Err(); e != nil {
			p.mu.Unlock()
			return e
		}
		if e = p.cmd.Process.Signal(syscall.SIGHUP); e != nil {
			p.mu.Unlock()
			return errors.New("Nginx reload failed")
		}
	}
	p.mu.Unlock()
	return p.waitGeneration(ctx, previous, version)
}
func (p *Process) waitGeneration(ctx context.Context, previous map[string]bool, version string) error {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	var lastCause error
	for {
		if e := ctx.Err(); e != nil {
			return errors.Join(e, lastCause, errors.New("Nginx version verification deadline"))
		}
		p.mu.Lock()
		workers, workerErr := p.workers()
		p.mu.Unlock()
		fresh := false
		for pid := range workers {
			if !previous[pid] {
				fresh = true
			}
		}
		retired, inspectionErr := p.retiredListeners(previous)
		// /proc tables, children and descriptors are separate lifecycle snapshots.
		// Unknown remains a refusal to acknowledge, but may be observed again only
		// within this original authority deadline; it never grants a fresh budget.
		if workerErr != nil {
			lastCause = workerErr
		}
		if inspectionErr != nil {
			lastCause = inspectionErr
		}
		if workerErr == nil && fresh && inspectionErr == nil && retired {
			actual, e := p.Observe(ctx)
			if e == nil && actual == version && ctx.Err() == nil {
				return nil
			}
			if e != nil {
				lastCause = e
			}
		}
		select {
		case <-ctx.Done():
			return errors.Join(ctx.Err(), lastCause, errors.New("Nginx version verification deadline"))
		case <-tick.C:
		}
	}
}

func (p *Process) Observe(ctx context.Context) (string, error) {
	p.mu.Lock()
	alive := p.running()
	p.mu.Unlock()
	if !alive {
		return "", edge.ErrNotRunning
	}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9090/version", nil)
	if e != nil {
		return "", e
	}
	resp, e := p.probe.Do(req)
	if e != nil {
		return "", errors.New("Nginx version probe failed")
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 1025))
	if e != nil || len(b) > 1024 || resp.StatusCode != 200 {
		return "", errors.New("invalid Nginx version probe")
	}
	return string(b), nil
}
func (p *Process) PID() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running() {
		return 0
	}
	return p.cmd.Process.Pid
}
func (p *Process) Stop(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	p.mu.Lock()
	if !p.running() {
		p.mu.Unlock()
		return nil
	}
	cmd, done := p.cmd, p.done
	e := cmd.Process.Signal(syscall.SIGQUIT)
	p.mu.Unlock()
	if e != nil {
		return e
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-done:
		case <-time.After(time.Second):
		}
		return ctx.Err()
	}
}
