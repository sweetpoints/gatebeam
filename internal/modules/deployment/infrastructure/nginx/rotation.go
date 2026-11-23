package nginx

import (
	"context"
	"errors"
	"fmt"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func (p *Process) RotateLogs(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running() {
		return edge.ErrNotRunning
	}
	dir := filepath.Join(p.root, "logs")
	rotated := []string{}
	suffix := time.Now().UTC().Format("20060102T150405.000000000")
	for _, name := range []string{"access", "error"} {
		path := filepath.Join(dir, name+".log")
		f, e := os.OpenFile(path, os.O_RDWR, 0600)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
		if e = os.Rename(path, filepath.Join(dir, fmt.Sprintf("%s.%s.log", name, suffix))); e != nil {
			return e
		}
		rotated = append(rotated, fmt.Sprintf("%s.%s.log", name, suffix))
		f, e = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		e = f.Sync()
		f.Close()
		if e != nil {
			return e
		}
	}
	d, e := os.Open(dir)
	if e != nil {
		return e
	}
	e = d.Sync()
	d.Close()
	if e != nil {
		return e
	}
	if e = p.cmd.Process.Signal(syscall.SIGUSR1); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		workers, e := p.workers()
		if e != nil {
			return e
		}
		workers[strconv.Itoa(p.cmd.Process.Pid)] = true
		reopened := true
		for pid := range workers {
			entries, e := os.ReadDir("/proc/" + pid + "/fd")
			if errors.Is(e, os.ErrNotExist) {
				continue
			}
			if e != nil {
				return e
			}
			for _, entry := range entries {
				target, e := os.Readlink("/proc/" + pid + "/fd/" + entry.Name())
				if e != nil {
					if errors.Is(e, os.ErrNotExist) {
						continue
					}
					return errors.New("cannot verify log descriptor ownership")
				}
				if strings.HasPrefix(target, dir+"/") && strings.Contains(target, suffix) {
					reopened = false
				}
			}
		}
		if reopened {
			// A zero-byte marker certifies that no native worker/master still
			// writes this renamed file. Ingest keeps unmarked tails pending.
			for _, name := range rotated {
				// Flush records written between the initial rename fsync and
				// the last old descriptor closing before certifying closure.
				segment, e := os.Open(filepath.Join(dir, name))
				if e != nil {
					return e
				}
				e = segment.Sync()
				segment.Close()
				if e != nil {
					return e
				}
				marker, e := os.OpenFile(filepath.Join(dir, name+".closed"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
				if e != nil {
					return e
				}
				e = marker.Sync()
				marker.Close()
				if e != nil {
					return e
				}
			}
			directory, e := os.Open(dir)
			if e != nil {
				return e
			}
			e = directory.Sync()
			directory.Close()
			if e != nil {
				return e
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
