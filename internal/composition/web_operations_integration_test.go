//go:build integration

package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/integration/notificationaccess"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/ingress"
	"gatebeam/internal/modules/notification"

	"gatebeam/internal/modules/notification/infrastructure/telegram"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/parquet"
	repo "gatebeam/internal/modules/observability/infrastructure/postgres"
	s3 "gatebeam/internal/modules/observability/infrastructure/s3"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type ownedProviderTransport struct {
	URL  *url.URL
	Base http.RoundTripper
}

func (t ownedProviderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	u := *c.URL
	u.Scheme = t.URL.Scheme
	u.Host = t.URL.Host
	c.URL = &u
	return t.Base.RoundTrip(c)
}

type operationsContainerQuery struct{ Volume string }

func (e operationsContainerQuery) Execute(ctx context.Context, f query.Filter, objects []domain.Object) ([]domain.QueryRow, error) {
	raw, _ := json.Marshal(struct {
		Filter  query.Filter
		Objects []domain.Object
	}{f, objects})
	cmd := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--user", "0:0", "--read-only", "--network", "none", "--cap-drop", "ALL", "--memory", "64m", "--cpus", "0.5", "--pids-limit", "64", "--log-driver", "none", "--label", "gatebeam.o5.run="+os.Getenv("GATEBEAM_TEST_OPERATIONS_RUN"), "-v", e.Volume+":/socket:ro", "curlimages/curl@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93", "--silent", "--fail-with-body", "--max-time", "60", "--unix-socket", "/socket/query.sock", "-H", "Content-Type: application/json", "--data-binary", "@-", "http://query/execute")
	cmd.Stdin = bytes.NewReader(raw)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return nil, domain.ErrQueryTimeout
		}
		if strings.TrimSpace(out.String()) == "capacity" {
			return nil, domain.ErrCapacity
		}
		if strings.TrimSpace(out.String()) == "busy" {
			return nil, domain.ErrQueryBusy
		}
		return nil, errors.New("owned query execution failed")
	}
	var rows []domain.QueryRow
	if json.Unmarshal(out.Bytes(), &rows) != nil {
		return nil, errors.New("owned query response invalid")
	}
	return rows, nil
}
func webOperations(t *testing.T, p *pgxpool.Pool) (bootstrap.Config, map[string]any) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	dir := t.TempDir()
	spool := filepath.Join(dir, "spool")
	a, b := uuid.NewString(), uuid.NewString()
	config := `{"enabled":true,"domains":["owned.test"],"maintenance":{"enabled":true,"status":503,"message":"owned"}}`
	fixtureTx, e := p.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer fixtureTx.Rollback(ctx)
	for i, id := range []string{a, b} {
		if _, e := fixtureTx.Exec(ctx, `INSERT INTO ingress_sites(id,name,draft_revision)VALUES($1,$2,1)`, id, fmt.Sprintf("运营站点 %s", []string{"A", "B"}[i])); e != nil {
			t.Fatal(e)
		}
		if _, e := fixtureTx.Exec(ctx, `INSERT INTO ingress_site_revisions(site_id,revision,config)VALUES($1,1,$2)`, id, config); e != nil {
			t.Fatal(e)
		}
	}
	if e = fixtureTx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	w, e := parquet.New(spool)
	if e != nil {
		t.Fatal(e)
	}
	cfg := s3.Config{Endpoint: os.Getenv("GATEBEAM_TEST_S3"), Bucket: "operations", Region: "us-east-1", AccessKey: "test-access-key", SecretKey: "test-secret-key"}
	store, e := s3.New(cfg, spool)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { store.Close() })
	if e = store.EnsureBucket(ctx); e != nil {
		t.Fatal(e)
	}
	tx, r := postgres.NewRunner(p), repo.New()
	at := time.Now().UTC().Truncate(time.Minute).Add(-2 * time.Minute)
	events := make([]domain.Event, 10102)
	for i := range events {
		route := "1"
		if i < 101 {
			route = "0"
		}
		events[i] = domain.Event{Time: at.Add(time.Duration(i) * time.Microsecond), SiteID: a, RequestID: fmt.Sprintf("%032x", i+1), Method: "GET", Route: route, Status: 200, Bytes: 128, Micros: 1000}
	}
	seg := domain.Segment{ID: strings.Repeat("a", 64), Fingerprint: "owned", Path: "access.log", Size: 11}
	if e = tx.Within(ctx, func(sc transaction.Scope) error { _, e := r.CursorWithin(sc, seg); return e }); e != nil {
		t.Fatal(e)
	}
	for start, n := 0, 0; start < len(events); start, n = start+1024, n+1 {
		end := min(start+1024, len(events))
		id := fmt.Sprintf("%064x", n+1)
		objects, e := w.Persist(ctx, id, events[start:end])
		if e != nil {
			t.Fatal(e)
		}
		batch := domain.Batch{ID: id, SegmentID: seg.ID, Start: int64(n), End: int64(n + 1), SourceChecksum: id, Objects: objects, Buckets: domain.Aggregate(events[start:end])}
		if e = tx.Within(ctx, func(sc transaction.Scope) error { return r.CommitWithin(sc, seg, batch) }); e != nil {
			t.Fatal(e)
		}
		m, e := store.Upload(ctx, batch)
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Within(ctx, func(sc transaction.Scope) error { return r.CommitManifestWithin(sc, m) }); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = p.Exec(ctx, `UPDATE observability_stats SET ingested_at=clock_timestamp()-interval '120 seconds'`); e != nil {
		t.Fatal(e)
	}
	// Product query-worker runs with neither database nor API/CA/notification keys.
	endpoint := "http://history-s3:9000"
	qcfg := bootstrap.Config{Mode: "query", Environment: "development", QueryCredentialsFile: "/fixture/r2.json", QuerySocket: "/socket/query.sock", QueryLocalDirectory: "/spool"}
	raw, _ := json.Marshal(qcfg)
	qpath := filepath.Join(dir, "query.json")
	if e = os.WriteFile(qpath, raw, 0600); e != nil {
		t.Fatal(e)
	}
	cfg.Endpoint = endpoint
	raw, _ = json.Marshal(cfg)
	if e = os.WriteFile(filepath.Join(dir, "r2.json"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	name := os.Getenv("GATEBEAM_TEST_OPERATIONS_RUN") + "-query"
	if os.Getenv("GATEBEAM_TEST_QUERY_IMAGE") == "" {
		t.Fatal("operations query image required")
	}
	docker := func(args ...string) error {
		c, stop := context.WithTimeout(context.Background(), 20*time.Second)
		defer stop()
		return exec.CommandContext(c, "docker", args...).Run()
	}
	volume := name + "-socket"
	if e = docker("volume", "create", "--label", "gatebeam.o5.run="+os.Getenv("GATEBEAM_TEST_OPERATIONS_RUN"), volume); e != nil {
		t.Fatal("query socket volume failed")
	}
	if e = docker("run", "-d", "--name", name, "--label", "gatebeam.o5.run="+os.Getenv("GATEBEAM_TEST_OPERATIONS_RUN"), "--network", os.Getenv("GATEBEAM_TEST_OPERATIONS_RUN")+"-network", "--read-only", "--user", "0:0", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "512m", "--cpus", "1", "--pids-limit", "64", "--ulimit", "nofile=12288:12288", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--tmpfs", "/tmp:size=1g,mode=1777", "-v", dir+":/fixture:ro", "-v", volume+":/socket", "-v", spool+":/spool:ro", os.Getenv("GATEBEAM_TEST_QUERY_IMAGE"), "--config", "/fixture/query.json"); e != nil {
		t.Fatal("owned query-worker start failed")
	}
	t.Cleanup(func() {
		defer docker("volume", "rm", volume)
		if e := docker("rm", "-f", name); e != nil {
			t.Error("query fixture cleanup failed")
		}
	})

	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		if e = docker("exec", name, "test", "-S", "/socket/query.sock"); e == nil {
			ready = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !ready {
		t.Fatal("real query-worker readiness deadline")
	}
	var paused atomic.Bool
	coordinator := query.NewCoordinator(NewHistory(p), operationsContainerQuery{Volume: volume})
	go func() {
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if paused.Load() {
					continue
				}
				if e := coordinator.Step(ctx); e != nil && !errors.Is(e, domain.ErrIncomplete) && ctx.Err() == nil {
					t.Error("query coordinator receipt failed")
					return
				}
			}
		}
	}()
	// Actual offline CLI failure writes the only safe report consumed by the API.
	reports := filepath.Join(dir, "reports")
	dbfile := filepath.Join(dir, "local-db")
	if e = os.WriteFile(dbfile, []byte(os.Getenv("GATEBEAM_TEST_DATABASE_URL")), 0600); e != nil {
		t.Fatal(e)
	}
	recoveryKey := filepath.Join(dir, "recovery.agekey")
	if e = secrets.EnsureIdentity(recoveryKey); e != nil {
		t.Fatal(e)
	}
	bad := filepath.Join(dir, "invalid.age")
	_ = os.WriteFile(bad, []byte("owned invalid encrypted artifact"), 0600)
	restoreCfg := bootstrap.Config{Mode: "backup-restore", Environment: "development", DatabaseFile: dbfile, RecoverySource: bad, RecoveryIdentityFile: recoveryKey, RecoveryDirectory: filepath.Join(dir, "isolated"), RecoveryReportDirectory: reports}
	raw, _ = json.Marshal(restoreCfg)
	restoreConfig := filepath.Join(dir, "restore.json")
	_ = os.WriteFile(restoreConfig, raw, 0600)
	cliCtx, stop := context.WithTimeout(ctx, 10*time.Second)
	defer stop()
	if e = exec.CommandContext(cliCtx, os.Getenv("GATEBEAM_WEB_LOCAL_BINARY"), "--config", restoreConfig).Run(); e == nil {
		t.Fatal("invalid offline restore unexpectedly succeeded")
	}
	if _, e = os.Stat(filepath.Join(reports, "latest-recovery-report.json")); e != nil {
		t.Fatal("actual local CLI failure did not persist safe report")
	}
	workerKey := filepath.Join(dir, "notification.agekey")
	if e = secrets.EnsureIdentity(workerKey); e != nil {
		t.Fatal(e)
	}
	workerSecret, e := secrets.New(workerKey)
	if e != nil {
		t.Fatal(e)
	}
	cat := &ingressaccess.Catalog{}
	access := identity.NewAccess(p, cat)
	sites := ingress.New(p, ingressaccess.Authorizer{Identity: access})
	cat.Ingress = sites
	_, delivery, e := notification.NewWorker(p, &notificationaccess.Security{Access: access, Ingress: sites, Background: true}, workerKey, workerSecret.Recipient())
	if e != nil {
		t.Fatal(e)
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	t.Cleanup(provider.Close)
	u, _ := url.Parse(provider.URL)
	delivery.Senders["telegram"] = telegram.Sender{Client: &http.Client{Transport: ownedProviderTransport{URL: u, Base: provider.Client().Transport}, Timeout: 2 * time.Second}}
	command, result := filepath.Join(dir, "command.json"), filepath.Join(dir, "result.json")
	go func() {
		tick := time.NewTicker(30 * time.Millisecond)
		defer tick.Stop()
		last := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				raw, e := os.ReadFile(command)
				if e != nil {
					continue
				}
				var cmd struct {
					Request int
					Action  string
				}
				if json.Unmarshal(raw, &cmd) != nil || cmd.Request <= last {
					continue
				}
				last = cmd.Request
				c, done := context.WithTimeout(ctx, 5*time.Second)
				var err error
				switch cmd.Action {
				case "pause":
					paused.Store(true)
				case "resume":
					paused.Store(false)
				case "coordinate-local":
					err = postgres.NewRunner(p).Within(c, func(sc transaction.Scope) error {
						var id string
						if e := p.QueryRow(c, `SELECT id::text FROM observability_queries WHERE state='queued' AND filter->>'source'='local' ORDER BY created_at DESC LIMIT 1`).Scan(&id); e != nil {
							return e
						}
						r := repo.New()
						in, _, e := r.FetchWithin(sc, id)
						if e != nil {
							return e
						}
						_, e = r.PrepareLocalWithin(sc, in.Job, []query.LocalNode{{NodeID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, {NodeID: "22222222-2222-4222-8222-222222222222", Epoch: 1}})
						return e
					})
				case "expire-local":
					_, err = p.Exec(c, `UPDATE observability_queries SET created_at=clock_timestamp()-interval '2 minutes' WHERE state='coordinating'`)
				case "mfa":
					_, err = p.Exec(c, `UPDATE identity_accounts SET last_step=-1 WHERE name='browser-admin'`)
				case "deliver":
					for i := 0; i < 5; i++ {
						_, err = p.Exec(c, `UPDATE notification_deliveries SET next_at=clock_timestamp() WHERE status='pending'`)
						if err == nil {
							err = delivery.Step(c)
						}
						if err != nil {
							break
						}
					}
				default:
					err = errors.New("unknown owned fixture action")
				}
				done()
				if err != nil {
					t.Error("operations fixture command failed")
				}
				out, _ := json.Marshal(map[string]any{"request": last, "failed": err != nil})
				_ = os.WriteFile(result, out, 0600)
			}
		}
	}()
	return bootstrap.Config{NotificationRecipient: workerSecret.Recipient(), RecoveryReportDirectory: reports}, map[string]any{"siteA": a, "siteB": b, "from": at.Add(-time.Minute).Format(time.RFC3339), "to": at.Add(time.Minute).Format(time.RFC3339), "workerCommand": command, "workerResult": result}
}
