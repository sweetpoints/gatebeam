//go:build integration

package logquery_test

import (
	"context"
	"errors"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/duckdb"
	"gatebeam/internal/modules/observability/infrastructure/parquet"
	objectstore "gatebeam/internal/modules/observability/infrastructure/s3"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (*objectstore.Store, *duckdb.Engine, domain.Manifest, string) {
	t.Helper()
	cfg := objectstore.Config{Endpoint: os.Getenv("GATEBEAM_TEST_S3"), Bucket: "history", AccessKey: "test-access-key", SecretKey: "test-secret-key", Region: "us-east-1"}
	if cfg.Endpoint == "" {
		t.Fatal("owned S3 fixture required")
	}
	root := t.TempDir()
	w, e := parquet.New(root)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	objects, e := w.Persist(t.Context(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []domain.Event{{Time: at, SiteID: "00000000-0000-0000-0000-000000000001", Method: "GET", Route: "0", Status: 200}})
	if e != nil {
		t.Fatal(e)
	}
	s, e := objectstore.New(cfg, root)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.EnsureBucket(t.Context()); e != nil {
		t.Fatal(e)
	}
	m, e := s.Upload(t.Context(), domain.Batch{ID: "fixture", Objects: objects})
	if e != nil {
		t.Fatal(e)
	}
	engine, e := duckdb.New(duckdb.Config{Binary: os.Getenv("GATEBEAM_TEST_DUCKDB"), Extension: os.Getenv("GATEBEAM_TEST_HTTPFS"), TempRoot: t.TempDir(), Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region, AccessKey: cfg.AccessKey, SecretKey: cfg.SecretKey})
	if e != nil {
		t.Fatal(e)
	}
	return s, engine, m, root
}
func TestR2HistoryAfterLocalDeletion(t *testing.T) {
	_, engine, m, root := fixture(t)
	if e := os.RemoveAll(root); e != nil {
		t.Fatal(e)
	}
	f := domain.QueryFilter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}
	rows, e := engine.Execute(t.Context(), f, m.Objects)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 || rows[0].Route != "0" {
		t.Fatalf("archived rows: %#v", rows)
	}
}

func TestLocalParquetQueryDoesNotRequireRemoteExtension(t *testing.T) {
	root := t.TempDir()
	writer, e := parquet.New(root)
	if e != nil {
		t.Fatal(e)
	}
	at := time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)
	site := "00000000-0000-0000-0000-000000000001"
	objects, e := writer.Persist(t.Context(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []domain.Event{{Time: at, SiteID: site, Method: "GET", Route: "0", Status: 200}})
	if e != nil {
		t.Fatal(e)
	}
	engine, e := duckdb.New(duckdb.Config{Binary: os.Getenv("GATEBEAM_TEST_DUCKDB"), Extension: filepath.Join(t.TempDir(), "missing-httpfs.duckdb_extension"), TempRoot: t.TempDir(), LocalRoot: root, Endpoint: "http://127.0.0.1:1"})
	if e != nil {
		t.Fatal(e)
	}
	filter := domain.QueryFilter{Source: "local", SiteIDs: []string{site}, From: at.Add(-time.Second), To: at.Add(time.Second)}
	rows, e := engine.Execute(t.Context(), filter, objects)
	if e != nil || len(rows) != 1 || rows[0].SiteID != site || rows[0].Route != "0" || rows[0].Status != 200 {
		t.Fatalf("local Parquet query required remote initialization: rows=%d error=%v", len(rows), e)
	}
	filter.Source = "archive"
	if _, e = engine.Execute(t.Context(), filter, objects); !errors.Is(e, duckdb.ErrUnavailable) {
		t.Fatalf("archive query accepted missing remote extension: %v", e)
	}
}

func TestObjectPathSQLAndScopeInjection(t *testing.T) {
	_, engine, m, _ := fixture(t)
	f := domain.QueryFilter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}
	for _, key := range []string{"s3://other/secret", "../../etc/passwd", "x'); INSTALL evil; --", "x*"} {
		bad := append([]domain.Object(nil), m.Objects...)
		bad[0].Key = key
		if _, e := engine.Execute(t.Context(), f, bad); e == nil {
			t.Fatalf("accepted %q", key)
		}
	}
	f.Route = "'; SELECT * FROM duckdb_secrets();--"
	if _, e := engine.Execute(t.Context(), f, m.Objects); e == nil {
		t.Fatal("SQL filter accepted")
	}
	f.Route = ""
	f.SiteIDs = []string{"00000000-0000-0000-0000-000000000002"}
	if _, e := engine.Execute(t.Context(), f, m.Objects); e == nil {
		t.Fatal("scope escape accepted")
	}
}
func TestQueryTimeoutKillsChildAndFreesSlot(t *testing.T) {
	_, engine, m, _ := fixture(t)
	f := domain.QueryFilter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, e := engine.Execute(ctx, f, m.Objects); e == nil {
		t.Fatal("cancel accepted")
	}
	if _, e := engine.Execute(t.Context(), f, m.Objects); e != nil {
		t.Fatal("slot not released", e)
	}
	entries, e := filepath.Glob(filepath.Join(engine.TempRoot(), "query-*"))
	if e != nil || len(entries) != 0 {
		t.Fatal("temporary files leaked", entries, e)
	}
}

func TestActiveDuckDBCancellationReleasesSlot(t *testing.T) {
	_, _, m, _ := fixture(t)
	upstream, e := url.Parse(os.Getenv("GATEBEAM_TEST_S3"))
	if e != nil {
		t.Fatal(e)
	}
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	var blocked atomic.Bool
	blocked.Store(true)
	entered := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if blocked.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-r.Context().Done()
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	engine, e := duckdb.New(duckdb.Config{Binary: os.Getenv("GATEBEAM_TEST_DUCKDB"), Extension: os.Getenv("GATEBEAM_TEST_HTTPFS"), TempRoot: t.TempDir(), Endpoint: server.URL, Bucket: "history", Region: "us-east-1", AccessKey: "test-access-key", SecretKey: "test-secret-key"})
	if e != nil {
		t.Fatal(e)
	}
	f := domain.QueryFilter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { _, e := engine.Execute(ctx, f, m.Objects); done <- e }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("real httpfs never issued request")
	}
	cancel()
	select {
	case e = <-done:
		if !errors.Is(e, duckdb.ErrTimeout) {
			t.Fatal(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("active DuckDB not cancelled")
	}
	blocked.Store(false)
	rows, e := engine.Execute(t.Context(), f, m.Objects)
	if e != nil || len(rows) != 1 {
		t.Fatal("slot did not recover", e)
	}
	entries, _ := filepath.Glob(filepath.Join(engine.TempRoot(), "query-*"))
	if len(entries) != 0 {
		t.Fatal("temp survived", entries)
	}
}

func TestExistingArchiveDigestConflictCannotOverwrite(t *testing.T) {
	_, engine, m, _ := fixture(t)
	root := t.TempDir()
	writer, e := parquet.New(root)
	if e != nil {
		t.Fatal(e)
	}
	objects, e := writer.Persist(t.Context(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", []domain.Event{{Time: m.Objects[0].MinTime, SiteID: m.Objects[0].SiteID, Method: "GET", Route: "0", Status: 201}})
	if e != nil {
		t.Fatal(e)
	}
	store, e := objectstore.New(objectstore.Config{Endpoint: os.Getenv("GATEBEAM_TEST_S3"), Bucket: "history", Region: "us-east-1", AccessKey: "test-access-key", SecretKey: "test-secret-key"}, root)
	if e != nil {
		t.Fatal(e)
	}
	defer store.Close()
	if _, e = store.Upload(t.Context(), domain.Batch{Objects: objects}); e == nil {
		t.Fatal("conflicting immutable object overwritten")
	}
	rows, e := engine.Execute(t.Context(), domain.QueryFilter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}, m.Objects)
	if e != nil || len(rows) != 1 || rows[0].Status != 200 {
		t.Fatal("original archive changed", rows, e)
	}
}

func TestMixedLegacyAndNodeArchivesKeepProvenance(t *testing.T) {
 store,engine,m,root:=fixture(t)
 node:="22222222-2222-4222-8222-222222222222"
 writer,e:=parquet.NewNode(root,node);if e!=nil{t.Fatal(e)}
 at:=m.Objects[0].MinTime
 objects,e:=writer.Persist(t.Context(),"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",[]domain.Event{{NodeID:node,Time:at,SiteID:m.Objects[0].SiteID,Method:"GET",Route:"0",Status:201}});if e!=nil{t.Fatal(e)}
 archived,e:=store.Upload(t.Context(),domain.Batch{ID:"node-fixture",NodeID:node,Objects:objects});if e!=nil{t.Fatal(e)}
 objects=append(m.Objects,archived.Objects...)
 if e=os.RemoveAll(root);e!=nil{t.Fatal(e)}
 rows,e:=engine.Execute(t.Context(),domain.QueryFilter{SiteIDs:[]string{m.Objects[0].SiteID},From:at.Add(-time.Second),To:at.Add(time.Second)},objects)
 if e!=nil||len(rows)!=2{t.Fatal(rows,e)}
 got:=map[string]bool{};for _,r:=range rows{got[r.NodeID]=true}
 if !got["legacy"]||!got[node]{t.Fatal("lost or invented archive provenance",got)}
}
