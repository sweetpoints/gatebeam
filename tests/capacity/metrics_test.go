//go:build capacity

package capacity_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

var requiredMetrics = map[string][]string{
	"memory.peak": nil, "memory.max": nil, "pids.peak": nil, "pids.max": nil,
	"memory.events": {"oom", "oom_kill"}, "memory.stat": {"anon", "file"}, "cpu.stat": {"usage_usec"},
}

func collectResources(root string, usage func(int, *syscall.Rusage) error) (map[string]string, error) {
	var r syscall.Rusage
	if err := usage(syscall.RUSAGE_CHILDREN, &r); err != nil {
		return nil, fmt.Errorf("required child RSS: %w", err)
	}
	out := map[string]string{"child_process_peak_rss_KiB": strconv.FormatInt(r.Maxrss, 10)}
	for name, keys := range requiredMetrics {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			return nil, fmt.Errorf("required %s: %w", name, err)
		}
		fields := strings.Fields(string(b))
		values := map[string]string{}
		if len(keys) == 0 {
			if len(fields) != 1 {
				return nil, fmt.Errorf("invalid %s", name)
			}
			values[name] = fields[0]
			keys = []string{name}
		} else {
			if len(fields)%2 != 0 {
				return nil, fmt.Errorf("invalid %s", name)
			}
			for i := 0; i < len(fields); i += 2 {
				values[fields[i]] = fields[i+1]
			}
		}
		for _, key := range keys {
			if _, err := strconv.ParseUint(values[key], 10, 64); err != nil {
				return nil, fmt.Errorf("required %s/%s unavailable", name, key)
			}
		}
		out[name] = strings.TrimSpace(string(b))
	}
	return out, nil
}
func TestRequiredCapacityMetrics(t *testing.T) {
	root := t.TempDir()
	values := map[string]string{"memory.peak": "1024", "memory.max": "536870912", "pids.peak": "3", "pids.max": "64", "memory.events": "oom 0\noom_kill 0", "memory.stat": "anon 1\nfile 2", "cpu.stat": "usage_usec 3"}
	for name, value := range values {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	usage := func(_ int, r *syscall.Rusage) error { r.Maxrss = 100; return nil }
	if v, err := collectResources(root, usage); err != nil || len(v) != 8 {
		t.Fatal(v, err)
	}
	for name, value := range values {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(root, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if _, err := collectResources(root, usage); err == nil {
				t.Fatal("missing required metric silently accepted")
			}
			if err := os.Mkdir(p, 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := collectResources(root, usage); err == nil {
				t.Fatal("unreadable required metric silently accepted")
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("unsupported"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := collectResources(root, usage); err == nil {
				t.Fatal("malformed required metric silently accepted")
			}
			if err := os.WriteFile(p, []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := collectResources(root, func(int, *syscall.Rusage) error { return errors.New("rusage unavailable") }); err == nil {
		t.Fatal("missing RSS accepted")
	}
}
