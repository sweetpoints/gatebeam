//go:build capacity

package capacity_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/duckdb"
	logparquet "gatebeam/internal/modules/observability/infrastructure/parquet"
	"gatebeam/internal/platform/objectstore"
	"github.com/aws/aws-sdk-go-v2/aws"
	sdk "github.com/aws/aws-sdk-go-v2/service/s3"
	pq "github.com/parquet-go/parquet-go"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const dataset = "/dataset"
const site = "00000000-0000-4000-8000-000000000001"

var at = time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC)

func integer(t *testing.T, key string) int {
	t.Helper()
	n, e := strconv.Atoi(os.Getenv(key))
	if e != nil || n < 1 {
		t.Fatal("explicit capacity dimension required", key)
	}
	return n
}
func readObjects(t *testing.T) []domain.Object {
	t.Helper()
	b, e := os.ReadFile(filepath.Join(dataset, "manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	var out []domain.Object
	if e = json.Unmarshal(b, &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func writeObjects(t *testing.T, objects []domain.Object) {
	t.Helper()
	b, e := json.Marshal(objects)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dataset, "manifest.json"), b, 0644); e != nil {
		t.Fatal(e)
	}
}
func resources(t *testing.T) {
	t.Helper()
	values, err := collectResources("/sys/fs/cgroup", syscall.Getrusage)
	if err != nil {
		t.Fatal("capacity measurement incomplete:", err)
	}
	for name, value := range values {
		t.Log(name, value)
	}
}
func TestCapacityPrepare(t *testing.T) {
	defer resources(t)
	rows, count, pattern := integer(t, "CAPACITY_ROWS"), integer(t, "CAPACITY_OBJECTS"), integer(t, "CAPACITY_PATTERN")
	if rows > 1000000 || count > 4096 || pattern > 2048 {
		t.Fatal("fixture dimension exceeds disk/work budget")
	}
	start := time.Now()
	rng := rand.New(rand.NewPCG(71, 91))
	objects := []domain.Object{}
	var total int64
	if e := os.MkdirAll(filepath.Join(dataset, site, "2026-11-07", "00"), 0755); e != nil {
		t.Fatal(e)
	}
	for object := 0; object < count; object++ {
		first, last := object*rows/count, (object+1)*rows/count
		key := fmt.Sprintf("%s/2026-11-07/00/%064x.parquet", site, object+1)
		f, e := os.Create(filepath.Join(dataset, key))
		if e != nil {
			t.Fatal(e)
		}
		writer := pq.NewGenericWriter[logparquet.Row](f, pq.Compression(&pq.Snappy), pq.MaxRowsPerRowGroup(1024), pq.KeyValueMetadata("schema_version", "1"))
		batch := make([]logparquet.Row, 0, 1024)
		for i := first; i < last; i++ {
			if e := t.Context().Err(); e != nil {
				t.Fatal(e)
			}
			path := make([]byte, pattern)
			path[0] = '/'
			for j := 1; j < len(path); {
				// Each character still has six random bits. Consume ten disjoint
				// groups per 64-bit draw rather than discarding 58 bits per byte.
				bits := rng.Uint64()
				for k := 0; k < 10 && j < len(path); k++ {
					path[j] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"[bits&63]
					bits >>= 6
					j++
				}
			}
			status := int32(200)
			if i%100000 == 0 {
				status = 599
			}
			batch = append(batch, logparquet.Row{SiteID: site, RequestID: fmt.Sprintf("%032x", i), Route: "0", Method: "GET", Time: at.Add(time.Duration(i) * time.Microsecond).UnixMicro(), Status: status, Bytes: 500, Micros: 1000, PathPattern: string(path), ConfigID: strings.Repeat("a", 64)})
			if len(batch) == 1024 {
				if _, e = writer.Write(batch); e != nil {
					t.Fatal(e)
				}
				batch = batch[:0]
			}
		}
		if len(batch) > 0 {
			if _, e = writer.Write(batch); e != nil {
				t.Fatal(e)
			}
		}
		if e = writer.Close(); e != nil {
			t.Fatal(e)
		}
		// Bound dirty page-cache charges while preparing the dataset within the
		// measured query's memory budget. A slow backing disk must
		// not accumulate the entire near-2GiB fixture as unreclaimable pages.
		if e = f.Sync(); e != nil {
			t.Fatal(e)
		}
		if e = f.Close(); e != nil {
			t.Fatal(e)
		}
		f, e = os.Open(filepath.Join(dataset, key))
		if e != nil {
			t.Fatal(e)
		}
		h := sha256.New()
		size, e := io.Copy(h, f)
		f.Close()
		if e != nil {
			t.Fatal(e)
		}
		if total+size > domain.MaxScanBytes {
			if e = os.Remove(filepath.Join(dataset, key)); e != nil {
				t.Fatal(e)
			}
			break
		}
		total += size
		objects = append(objects, domain.Object{SchemaVersion: 1, SiteID: site, Hour: "2026-11-07/00", Key: key, Checksum: hex.EncodeToString(h.Sum(nil)), Rows: int64(last - first), Bytes: size, MinTime: at.Add(time.Duration(first) * time.Microsecond), MaxTime: at.Add(time.Duration(last-1) * time.Microsecond)})
	}
	if len(objects) == 0 || pattern >= 2000 && total < 1900<<20 {
		t.Fatal("near-limit fixture not actually near 2 GiB", total)
	}
	writeObjects(t, objects)
	t.Logf("prepared rows_requested=%d objects_actual=%d manifest_bytes=%d elapsed=%s", rows, len(objects), total, time.Since(start))
}
func s3config() objectstore.Config {
	return objectstore.Config{Endpoint: "http://capacity-s3:9000", Bucket: "capacity", Region: "us-east-1", AccessKey: "owned-capacity", SecretKey: "owned-capacity-secret"}
}
func TestCapacityUpload(t *testing.T) {
	defer resources(t)
	client := objectstore.Client(s3config())
	bucket := s3config().Bucket
	if _, e := client.CreateBucket(t.Context(), &sdk.CreateBucketInput{Bucket: &bucket}); e != nil {
		t.Fatal("owned capacity bucket unavailable")
	}
	start := time.Now()
	objects := readObjects(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	queue := make(chan domain.Object)
	var group sync.WaitGroup
	var failed atomic.Bool
	var uploaded, completed atomic.Int64
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for object := range queue {
				if ctx.Err() != nil {
					return
				}
				f, e := os.Open(filepath.Join(dataset, object.Key))
				if e == nil {
					_, e = client.PutObject(ctx, &sdk.PutObjectInput{Bucket: &bucket, Key: aws.String("logs/" + object.Key), Body: f, ContentLength: &object.Bytes})
					f.Close()
				}
				if e != nil {
					failed.Store(true)
					cancel()
					return
				}
				uploaded.Add(object.Bytes)
				completed.Add(1)
			}
		}()
	}
enqueue:
	for _, object := range objects {
		select {
		case <-ctx.Done():
			break enqueue
		case queue <- object:
		}
	}
	close(queue)
	group.Wait()
	if failed.Load() || completed.Load() != int64(len(objects)) {
		t.Fatal("owned capacity upload failed")
	}
	t.Logf("uploaded actual_bytes=%d objects=%d concurrency=4 elapsed=%s", uploaded.Load(), completed.Load(), time.Since(start))
}

type countedBody struct {
	io.ReadCloser
	bytes *atomic.Int64
}

func (b countedBody) Read(p []byte) (int, error) {
	n, e := b.ReadCloser.Read(p)
	b.bytes.Add(int64(n))
	return n, e
}
func TestLogQueryCapacity(t *testing.T) {
	if err := duckdb.CheckOpenFileBudget(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer resources(t)
	objects := readObjects(t)
	source := os.Getenv("CAPACITY_SOURCE")
	if source != "local" && source != "archive" {
		t.Fatal("explicit capacity source required")
	}
	var gets, heads, bytes atomic.Int64
	target, _ := url.Parse(s3config().Endpoint)
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ModifyResponse = func(r *http.Response) error { r.Body = countedBody{r.Body, &bytes}; return nil }
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			gets.Add(1)
		}
		if r.Method == "HEAD" {
			heads.Add(1)
		}
		proxy.ServeHTTP(w, r)
	}))
	defer server.Close()
	cfg := s3config()
	cfg.Endpoint = server.URL
	engine, e := duckdb.New(duckdb.Config{Binary: "/usr/local/bin/duckdb", Extension: "/opt/duckdb/httpfs.duckdb_extension", TempRoot: t.TempDir(), LocalRoot: dataset, Endpoint: cfg.Endpoint, Bucket: cfg.Bucket, Region: cfg.Region, AccessKey: cfg.AccessKey, SecretKey: cfg.SecretKey, Timeout: 60 * time.Second})
	if e != nil {
		t.Fatal(e)
	}
	filter := domain.QueryFilter{Source: source, SiteIDs: []string{site}, From: at, To: at.Add(2 * time.Second), Status: 599}
	if os.Getenv("CAPACITY_SPAN") == "narrow" {
		filter.To = at.Add(100 * time.Millisecond)
		selected := objects[:0]
		for _, o := range objects {
			if o.MinTime.Before(filter.To) {
				selected = append(selected, o)
			}
		}
		objects = selected
	}
	var manifestBytes, rows int64
	for _, o := range objects {
		manifestBytes += o.Bytes
		rows += o.Rows
	}

	assertClosed := func() {
		t.Helper()
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			target, _ := os.Readlink("/proc/self/fd/" + entry.Name())
			if strings.HasPrefix(target, dataset+"/") {
				t.Fatal("verified dataset descriptor leaked after query")
			}
		}
	}
	if source == "local" && os.Getenv("CAPACITY_SPAN") != "narrow" {
		canceled, cancel := context.WithTimeout(t.Context(), time.Millisecond)
		_, err := engine.Execute(canceled, filter, objects)
		cancel()
		if err == nil {
			t.Fatal("canceled hash/query unexpectedly succeeded")
		}
		assertClosed()
		t.Log("canceled local verification released all dataset descriptors")
	}
	start := time.Now()
	result, e := engine.Execute(t.Context(), filter, objects)
	elapsed := time.Since(start)
	if source == "local" {
		assertClosed()
	}
	// A capacity refusal or timeout is an observed failed gate, never a skipped
	// subsystem or a falsely successful empty result.
	if e != nil {
		t.Fatalf("capacity query source=%s manifest_bytes=%d objects=%d elapsed=%s GET=%d HEAD=%d read_bytes=%d error=%v", source, manifestBytes, len(objects), elapsed, gets.Load(), heads.Load(), bytes.Load(), e)
	}
	expected := 1
	if os.Getenv("CAPACITY_SPAN") != "narrow" {
		expected = (integer(t, "CAPACITY_ROWS") + 99999) / 100000
	}
	if len(result) != expected {
		t.Fatalf("known synthetic result count=%d want=%d", len(result), expected)
	}
	for i, row := range result {
		if row.RequestID != fmt.Sprintf("%032x", i*100000) || row.SiteID != site || row.Status != 599 {
			t.Fatal("synthetic query returned wrong row identity/status")
		}
	}
	t.Logf("capacity source=%s cache=%s span=%s rows=%d objects=%d manifest_bytes=%d elapsed=%s GET=%d HEAD=%d read_bytes=%d result_rows=%d concurrency=1", source, os.Getenv("CAPACITY_CACHE"), os.Getenv("CAPACITY_SPAN"), rows, len(objects), manifestBytes, elapsed, gets.Load(), heads.Load(), bytes.Load(), len(result))
}
