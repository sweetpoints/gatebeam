//go:build native

package runtime_test

import (
	"context"
	"errors"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOfflineLogRotationPreservesUnarchivedData(t *testing.T) {
	_, disk, process, _, compiler := realHarness(t)
	route(t)
	pid := process.PID()
	before, e := os.ReadFile(filepath.Join(compiler.root, "logs/access.log"))
	if e != nil || len(before) == 0 {
		t.Fatal("native access log missing", e)
	}
	policy := edge.LocalLogPolicy{Volume: disk, Process: process, RotateBytes: 1, MaxBytes: 1 << 20, MaxFiles: 128, Now: time.Now}
	if e = edge.MaintainLocalLogs(context.Background(), policy); e != nil {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(filepath.Join(compiler.root, "logs"))
	if e != nil {
		t.Fatal(e)
	}
	found := false
	preserved := map[string][]byte{}
	for _, entry := range entries {
		if entry.Name() != "access.log" && strings.HasPrefix(entry.Name(), "access.") && strings.HasSuffix(entry.Name(), ".log") {
			body, e := os.ReadFile(filepath.Join(compiler.root, "logs", entry.Name()))
			if e != nil {
				t.Fatal(e)
			}
			preserved[entry.Name()] = body
			found = found || strings.HasPrefix(string(body), string(before))
		}
	}
	if !found {
		t.Fatal("rotation lost unarchived prefix")
	}
	if process.PID() != pid {
		t.Fatal("log rotation restarted Nginx")
	}
	route(t)
	policy.MaxBytes = 1
	if e = edge.MaintainLocalLogs(context.Background(), policy); !errors.Is(e, edge.ErrLogCapacity) {
		t.Fatal("offline log pressure not explicit", e)
	}
	for name, body := range preserved {
		got, e := os.ReadFile(filepath.Join(compiler.root, "logs", name))
		if e != nil || string(got) != string(body) {
			t.Fatal("unarchived log deleted or overwritten under pressure", name, e)
		}
	}
	watermark, e := disk.LogWatermark(context.Background())
	if e != nil || !watermark.Capacity {
		t.Fatal("pressure watermark not durable", watermark, e)
	}
	route(t)
}
