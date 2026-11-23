package duckdb

import (
	"context"
	"errors"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCancellationKillsProcessGroupAndCleansSlot(t *testing.T) {
	dir := t.TempDir()
	pidfile := filepath.Join(dir, "child")
	binary := filepath.Join(dir, "fake-cli")
	if e := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 30 &\necho $! > '"+pidfile+"'\nwait\n"), 0700); e != nil {
		t.Fatal(e)
	}
	engine, e := New(Config{Binary: binary, Extension: filepath.Join(dir, "httpfs.duckdb_extension"), TempRoot: dir, Endpoint: "http://127.0.0.1:1", Bucket: "history", Timeout: 3 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	site := "11111111-1111-4111-8111-111111111111"
	f := domain.QueryFilter{SiteIDs: []string{site}, From: now, To: now.Add(time.Hour)}
	o := domain.Object{SchemaVersion: 1, SiteID: site, Key: site + "/2026-11-07/12/" + strings.Repeat("a", 64) + ".parquet", Hour: "2026-11-07/12", Checksum: strings.Repeat("b", 64), Bytes: 1, Rows: 1, MinTime: now, MaxTime: now}
	if _, e = engine.Execute(t.Context(), f, []domain.Object{o}); !errors.Is(e, ErrTimeout) {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(pidfile)
	if e != nil {
		t.Fatal("child never started", e)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	// A container PID 1 may not reap orphaned children. kill(pid, 0) then
	// still finds a zombie even though it cannot execute or retain open files.
	// Verify termination, rather than requiring the container init to reap it.
	running := func() bool {
		if syscall.Kill(pid, 0) != nil {
			return false
		}
		if runtime.GOOS == "linux" {
			status, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
			if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
				return false
			}
			if err == nil {
				end := strings.LastIndex(string(status), ") ")
				if end >= 0 && strings.HasPrefix(string(status[end+2:]), "Z ") {
					return false
				}
			}
		}
		return true
	}
	deadline := time.Now().Add(time.Second)
	for running() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if running() {
		status, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		t.Fatal("child survived cancellation", pid, "process status:", string(status))
	}
	files, _ := filepath.Glob(filepath.Join(dir, "query-*"))
	if len(files) != 0 {
		t.Fatal("temp leaked", files)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e = engine.Execute(ctx, f, []domain.Object{o}); !errors.Is(e, ErrTimeout) {
		t.Fatal(e)
	}
	if len(engine.slot) != 0 {
		t.Fatal("slot leaked")
	}
	if e = os.WriteFile(binary, []byte("#!/bin/sh\nprintf '[]'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Execute(t.Context(), f, []domain.Object{o}); e != nil {
		t.Fatal(fmt.Sprint("slot not reusable: ", e))
	}
}

func TestRestartRemovesOnlyOwnedTemporaryDirectories(t *testing.T) {
	root := t.TempDir()
	stale := filepath.Join(root, "query-stale")
	if e := os.Mkdir(stale, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(stale, "spill"), []byte("temporary"), 0600); e != nil {
		t.Fatal(e)
	}
	keep := filepath.Join(root, "unrelated")
	if e := os.WriteFile(keep, []byte("keep"), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := New(Config{Binary: "/usr/local/bin/duckdb", Extension: "/opt/duckdb/httpfs.duckdb_extension", TempRoot: root, Endpoint: "http://127.0.0.1:1"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(stale); !os.IsNotExist(e) {
		t.Fatal("crash spill not reconciled")
	}
	if _, e = os.Stat(keep); e != nil {
		t.Fatal("unowned file removed")
	}
}

func TestArchiveSQLBindsProvenanceFromManifest(t *testing.T) {
	dir := t.TempDir()
	capture := filepath.Join(dir, "sql")
	binary := filepath.Join(dir, "cli")
	if e := os.WriteFile(binary, []byte("#!/bin/sh\ncat > '"+capture+"'\nprintf '[]'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	engine, e := New(Config{Binary: binary, Extension: "/owned/httpfs.duckdb_extension", TempRoot: t.TempDir(), Endpoint: "http://127.0.0.1:1", Bucket: "history"})
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now()
	site := "11111111-1111-4111-8111-111111111111"
	node := "22222222-2222-4222-8222-222222222222"
	object := domain.Object{SchemaVersion: 2, NodeID: node, SiteID: site, Hour: "2026-11-07/12", Key: site + "/2026-11-07/12/" + node + "/" + strings.Repeat("a", 64) + ".parquet", Checksum: strings.Repeat("b", 64), Rows: 1, Bytes: 1, MinTime: at, MaxTime: at}
	if _, e = engine.Execute(t.Context(), domain.QueryFilter{SiteIDs: []string{site}, From: at.Add(-time.Second), To: at.Add(time.Second)}, []domain.Object{object}); e != nil {
		t.Fatal(e)
	}
	sql, e := os.ReadFile(capture)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(sql), "AS node_id") || !strings.Contains(string(sql), "THEN '"+node+"'") || !strings.Contains(string(sql), "union_by_name=true") {
		t.Fatal("query has no trusted source attribution or mixed schema compatibility")
	}
}
