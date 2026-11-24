//go:build integration

package multinode_test

import (
	"bytes"
	"context"
	"encoding/json"
	fixture "gatebeam/tests/fixtures/multinode"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type measuredPhase struct {
	Concurrency      int     `json:"concurrency"`
	Seconds          float64 `json:"seconds"`
	Requests, Errors int64
	RPS, P95Millis   float64
}

func TestSingleNodeMeasuredCapacityWithQueryContention(t *testing.T) {
	l := fixture.Start(t)
	business := l.Business(t)
	a, b := l.Nodes[0], l.Nodes[1]
	archive := l.EnableArchive(t)
	archive.WaitBoth(t)
	b.Compose(t, "stop", "--timeout", "2", "nginx", "management", "background-jobs", "log-query")
	for j := 0; j < 20; j++ {
		if business.Get(t, a, "/") != 200 {
			t.Fatal("warmup failed")
		}
	}
	time.Sleep(1100 * time.Millisecond)
	readyInput := false
	until := time.Now().Add(8 * time.Second)
	for time.Now().Before(until) {
		page := business.Query(t, "archive")
		if page.Job.State == "succeeded" && len(page.Rows) > 0 {
			readyInput = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !readyInput {
		t.Fatal("no actual archived Parquet query input")
	}
	ctx, cancel := context.WithCancel(t.Context())
	var queries, queryErrors atomic.Int64
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if e := measureQuery(ctx, a, business); e != nil {
				if ctx.Err() == nil {
					queryErrors.Add(1)
				}
			} else {
				queries.Add(1)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	phases := []measuredPhase{}
	for _, concurrency := range []int{1, 8, 32} {
		sample, cancelSample := context.WithTimeout(t.Context(), 2*time.Second)
		started := time.Now()
		var count, fail atomic.Int64
		var mu sync.Mutex
		latencies := []float64{}
		var workers sync.WaitGroup
		for j := 0; j < concurrency; j++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				for sample.Err() == nil {
					begin := time.Now()
					r, e := business.Clients[a.Info.Node.ID].Get("https://service.dual.test/")
					if e != nil {
						fail.Add(1)
					} else {
						body, readErr := io.ReadAll(io.LimitReader(r.Body, 1024))
						r.Body.Close()
						if r.StatusCode != 200 || readErr != nil || string(body) != "owned-business" {
							fail.Add(1)
						}
					}
					count.Add(1)
					mu.Lock()
					latencies = append(latencies, float64(time.Since(begin))/float64(time.Millisecond))
					mu.Unlock()
				}
			}()
		}
		workers.Wait()
		cancelSample()
		elapsed := time.Since(started).Seconds()
		slices.Sort(latencies)
		p95 := 0.0
		if len(latencies) > 0 {
			p95 = latencies[(len(latencies)-1)*95/100]
		}
		phases = append(phases, measuredPhase{Concurrency: concurrency, Seconds: elapsed, Requests: count.Load(), Errors: fail.Load(), RPS: float64(count.Load()-fail.Load()) / elapsed, P95Millis: p95})
	}
	cancel()
	<-done
	if queries.Load() == 0 {
		t.Fatal("no real concurrent DuckDB query completed")
	}
	best := 0.0
	for _, phase := range phases {
		if phase.Errors == 0 && phase.RPS > best {
			best = phase.RPS
		}
	}
	if best == 0 {
		t.Fatal("no error-free measured phase")
	}
	stats := map[string]json.RawMessage{}
	limits := map[string]json.RawMessage{}
	for role := range fixture.Modes {
		id := a.Compose(t, "ps", "-q", role)
		raw := fixture.Docker(t, "stats", "--no-stream", "--format", "{{json .}}", id)
		stats[role] = json.RawMessage(raw)
		raw = fixture.Docker(t, "inspect", "--format", "{{json .HostConfig}}", id)
		var all map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &all) != nil {
			t.Fatal("limits")
		}
		selected, _ := json.Marshal(map[string]json.RawMessage{"Memory": all["Memory"], "NanoCpus": all["NanoCpus"], "PidsLimit": all["PidsLimit"]})
		limits[role] = selected
	}
	report := map[string]any{"kind": "fixture", "required_peak_rps": 0, "production_peak_known": false, "node": a.Info.Node, "workload": "new HTTPS/TLS connections to actual published site and private HTTP backend, concurrent real S3 archived Parquet/DuckDB queries; peer five roles stopped; object store is in the same owned Docker VM", "host_os": runtime.GOOS, "host_arch": runtime.GOARCH, "host_cpus": runtime.NumCPU(), "docker_vm_cpus": fixture.Docker(t, "info", "--format", "{{.NCPU}}"), "phases": phases, "observed_error_free_rps": best, "queries_completed": queries.Load(), "query_errors": queryErrors.Load(), "docker_stats": stats, "runtime_limits": limits, "gateway_images": a.Info.Roles, "manifest": os.Getenv("GATEBEAM_MULTINODE_MANIFEST")}
	raw, e := json.MarshalIndent(report, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	out := os.Getenv("GATEBEAM_MULTINODE_REPORT")
	if out != "" {
		if e = os.MkdirAll(out, 0700); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(out, "single-node-capacity.json"), append(raw, '\n'), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Logf("owned fixture measured max error-free %.2f new TLS requests/s, query completions=%d errors=%d, phases=%+v; no production peak/SLA claim", best, queries.Load(), queryErrors.Load(), phases)
}
func measureQuery(ctx context.Context, n *fixture.Node, b *fixture.Business) error {
	call := func(method, path string, raw []byte) (*http.Response, error) {
		req, e := http.NewRequestWithContext(ctx, method, "https://management.dual.test"+path, bytes.NewReader(raw))
		if e != nil {
			return nil, e
		}
		req.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: b.Session.Cookie})
		if method == "POST" {
			req.Header.Set("Origin", "https://management.dual.test")
			req.Header.Set("X-CSRF-Token", b.Session.CSRF)
			req.Header.Set("Content-Type", "application/json")
		}
		return n.PublicClient.Do(req)
	}
	raw, _ := json.Marshal(map[string]any{"source": "archive", "SiteIDs": []string{b.SiteID}, "From": time.Now().Add(-time.Hour), "To": time.Now().Add(time.Minute)})
	r, e := call("POST", "/log-queries", raw)
	if e != nil {
		return e
	}
	var job struct{ ID string }
	e = json.NewDecoder(r.Body).Decode(&job)
	r.Body.Close()
	if e != nil || job.ID == "" {
		return context.DeadlineExceeded
	}
	for ctx.Err() == nil {
		r, e = call("GET", "/log-queries/"+job.ID, nil)
		if e != nil {
			return e
		}
		var page struct{ Job struct{ State string } }
		e = json.NewDecoder(r.Body).Decode(&page)
		r.Body.Close()
		if e != nil {
			return e
		}
		if page.Job.State == "succeeded" {
			return nil
		}
		if page.Job.State == "failed" {
			return context.DeadlineExceeded
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(40 * time.Millisecond):
		}
	}
	return ctx.Err()
}
