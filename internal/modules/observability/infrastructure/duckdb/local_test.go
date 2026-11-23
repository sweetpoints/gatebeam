package duckdb

import (
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/parquet"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalQueryRejectsChangedFrozenBytesBeforeStartingCLI(t *testing.T) {
	root := t.TempDir()
	w, e := parquet.New(root)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Now()
	site := "11111111-1111-4111-8111-111111111111"
	objects, e := w.Persist(t.Context(), strings.Repeat("a", 64), []domain.Event{{Time: at, SiteID: site, Route: "0", Method: "GET", Status: 200}})
	if e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(t.TempDir(), "started")
	binary := filepath.Join(t.TempDir(), "cli")
	if e = os.WriteFile(binary, []byte("#!/bin/sh\ntouch '"+marker+"'\nprintf '[]'\n"), 0700); e != nil {
		t.Fatal(e)
	}
	engine, e := New(Config{Binary: binary, Extension: "/owned/httpfs.duckdb_extension", TempRoot: t.TempDir(), LocalRoot: root, Endpoint: "http://127.0.0.1:1"})
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(root, objects[0].Key)
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	raw[0] ^= 1
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = engine.Execute(t.Context(), domain.QueryFilter{Source: "local", SiteIDs: []string{site}, From: at.Add(-time.Second), To: at.Add(time.Second)}, objects); e == nil {
		t.Fatal("changed local Parquet accepted")
	}
	if _, e = os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("CLI started before frozen-byte verification")
	}
}
