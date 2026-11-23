//go:build native

package runtime_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	fs "gatebeam/internal/modules/deployment/infrastructure/filesystem"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type nativeCompiler struct {
	root          string
	streamAddress string
	invalid       bool
}

func (c *nativeCompiler) Compile(s app.Snapshot, r edge.RuntimeState) (edge.Artifact, error) {
	data := fmt.Sprintf("worker_processes 1; worker_shutdown_timeout 1s; pid %s/nginx.pid; error_log %s/logs/error.log warn; events{worker_connections 32;} http{client_body_temp_path /tmp/body;proxy_temp_path /tmp/proxy;fastcgi_temp_path /tmp/fastcgi;uwsgi_temp_path /tmp/uwsgi;scgi_temp_path /tmp/scgi;access_log %s/logs/access.log; server{listen 127.0.0.1:9090;location /version{return 200 '%s/%s';}location /{return 200 'route-live';}}}", c.root, c.root, c.root, s.Version, r.Generation)
	if c.streamAddress != "" {
		data = strings.Replace(data, "worker_shutdown_timeout 1s;", "worker_shutdown_timeout 30s;", 1)
		data = strings.Replace(data, "location /{", fmt.Sprintf("location /stream { proxy_pass http://%s; proxy_buffering off; } location /{", c.streamAddress), 1)
	}
	if c.invalid {
		data = "invalid nginx directive;"
	}
	name := "nginx.conf"
	h := sha256.New()
	fmt.Fprintf(h, "%d:%s:%d:", len(name), name, len(data))
	h.Write([]byte(data))
	id := hex.EncodeToString(h.Sum(nil))
	return edge.Artifact{ID: id, Digest: id, Files: map[string][]byte{name: []byte(data)}}, nil
}
func realHarness(t *testing.T, streamAddress ...string) (*edge.Supervisor, *fs.Store, *nginx.Process, *authority, *nativeCompiler) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "runtime")
	disk, e := fs.New(root)
	if e != nil {
		t.Fatal(e)
	}
	p, e := nginx.NewProcess("/usr/sbin/nginx", root)
	if e != nil {
		t.Fatal(e)
	}
	c := &nativeCompiler{root: root}
	if len(streamAddress) > 0 {
		c.streamAddress = streamAddress[0]
	}
	a := &authority{old: edge.Plan{Snapshot: app.Snapshot{Version: "old"}, Runtime: edge.RuntimeState{Generation: "g1"}}, new: edge.Plan{Snapshot: app.Snapshot{Version: "old"}, Runtime: edge.RuntimeState{Generation: "g1"}}}
	s := edge.NewSupervisor(p, disk, disk, c, a)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if e := s.Stop(ctx); e != nil {
			t.Error(e)
		}
	})
	if r, e := s.Apply(context.Background(), "old"); e != nil {
		t.Fatalf("initial native apply: %+v %v", r, e)
	}
	a.new = edge.Plan{Snapshot: app.Snapshot{Version: "new"}, Runtime: edge.RuntimeState{Generation: "g2"}}
	t.Logf("real supervisor parent PID=%d Nginx child PID=%d", os.Getpid(), p.PID())
	return s, disk, p, a, c
}
func route(t *testing.T) {
	t.Helper()
	c := &http.Client{Timeout: time.Second}
	r, e := c.Get("http://127.0.0.1:9090/")
	if e != nil {
		t.Fatal(e)
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, 1024))
	if e != nil || string(b) != "route-live" {
		t.Fatalf("route %s %v", b, e)
	}
}
func TestNativeValidationFailureKeepsOldConfig(t *testing.T) {
	s, _, p, _, c := realHarness(t)
	c.invalid = true
	if r, e := s.Apply(context.Background(), "new"); e == nil || r.State != "failed" {
		t.Fatalf("invalid accepted %+v %v", r, e)
	}
	v, e := p.Observe(context.Background())
	if e != nil || v != "old/g1" {
		t.Fatalf("actual=%s %v", v, e)
	}
	route(t)
}
func TestNativeCrashAfterSwitchReconciles(t *testing.T) {
	s, d, p, a, c := realHarness(t)
	artifact, e := c.Compile(a.new.Snapshot, a.new.Runtime)
	if e != nil {
		t.Fatal(e)
	}
	path, e := d.Stage(context.Background(), artifact)
	if e != nil {
		t.Fatal(e)
	}
	if e = p.Validate(context.Background(), path); e != nil {
		t.Fatal(e)
	}
	j := domain.ApplyJournal{CandidateID: "new", ArtifactID: artifact.ID, Version: "new/g2", PreviousVersion: "old/g1", State: domain.Applying, ReceiptPending: true}
	if e = d.Save(context.Background(), j); e != nil {
		t.Fatal(e)
	}
	if e = d.Switch(context.Background(), artifact.ID); e != nil {
		t.Fatal(e)
	}
	if e = p.Activate(context.Background(), "new/g2"); e != nil {
		t.Fatal(e)
	}
	// Re-create both process ownership and supervisor from durable storage after
	// interruption between HUP and DB receipt. Current symlink points at the
	// uncommitted new artifact; recovery must compile the current-safe old config.
	previousPID := p.PID()
	if e = p.Stop(context.Background()); e != nil {
		t.Fatal(e)
	}
	restarted, e := nginx.NewProcess("/usr/sbin/nginx", c.root)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })
	recovered := edge.NewSupervisor(restarted, d, d, c, a)
	r, e := recovered.Recover(context.Background())
	if e != nil || r.Version != "old/g1" || r.State != "restored" {
		t.Fatalf("recovery %+v %v", r, e)
	}
	if restarted.PID() == 0 || restarted.PID() == previousPID {
		t.Fatal("process ownership was not reconstructed")
	}
	t.Logf("reconstructed process owner oldchild=%d newchild=%d", previousPID, restarted.PID())
	route(t)
	_ = s
}
func TestNativeLostDatabaseDoesNotExitNginx(t *testing.T) {
	s, _, p, a, _ := realHarness(t)
	pid := p.PID()
	a.down = true
	if _, e := s.Apply(context.Background(), "new"); e == nil {
		t.Fatal("database loss accepted")
	}
	if p.PID() != pid {
		t.Fatal("database failure restarted child")
	}
	route(t)
}
func TestNativeDurableLogRotationReopens(t *testing.T) {
	s, _, _, _, c := realHarness(t)
	route(t)
	if e := s.RotateLogs(context.Background()); e != nil {
		t.Fatal(e)
	}
	route(t)
	deadline := time.Now().Add(time.Second)
	for {
		b, e := os.ReadFile(filepath.Join(c.root, "logs", "access.log"))
		if e == nil && len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			entries, _ := os.ReadDir(filepath.Join(c.root, "logs"))
			for _, entry := range entries {
				data, _ := os.ReadFile(filepath.Join(c.root, "logs", entry.Name()))
				t.Logf("%s: %s", entry.Name(), data)
			}
			t.Fatalf("USR1 did not reopen access log: %v", e)
		}
		time.Sleep(10 * time.Millisecond)
	}
	files, e := filepath.Glob(filepath.Join(c.root, "logs", "access.*.log"))
	if e != nil || len(files) != 1 {
		t.Fatalf("durable rotation segment: %v %v", files, e)
	}
}

func TestNativeHUPKeepsOldSSEWhileNewConnectionsUseNewVersion(t *testing.T) {
	releaseAfterReload := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: before\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-releaseAfterReload:
		case <-r.Context().Done():
			return
		}
		fmt.Fprint(w, "data: after\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer backend.Close()
	supervisor, _, process, _, _ := realHarness(t, backend.Listener.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:9090/stream", nil)
	if e != nil {
		t.Fatal(e)
	}
	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	event := func() string {
		line, e := reader.ReadString('\n')
		if e != nil {
			t.Fatal(e)
		}
		blank, e := reader.ReadString('\n')
		if e != nil || blank != "\n" {
			t.Fatalf("invalid streamed event delimiter %q %v", blank, e)
		}
		return line
	}
	if got := event(); got != "data: before\n" {
		t.Fatal(got)
	}
	children, e := os.ReadFile(fmt.Sprintf("/proc/%d/task/%d/children", process.PID(), process.PID()))
	if e != nil {
		t.Fatal(e)
	}
	old := strings.Fields(string(children))
	if len(old) != 1 {
		t.Fatalf("expected one initial worker: %q", children)
	}
	apply, cancelApply := context.WithTimeout(ctx, 3*time.Second)
	defer cancelApply()
	result, e := supervisor.Apply(apply, "new")
	if e != nil || result.Version != "new/g2" {
		t.Fatalf("HUP blocked on old stream or failed: %+v %v", result, e)
	}
	if _, e = os.Stat("/proc/" + old[0]); e != nil {
		t.Fatalf("old streaming worker already exited: %v", e)
	}
	if actual, e := process.Observe(ctx); e != nil || actual != "new/g2" {
		t.Fatalf("new connection sees %s %v", actual, e)
	}
	close(releaseAfterReload)
	if got := event(); got != "data: after\n" {
		t.Fatal(got)
	}
	t.Logf("old SSE worker PID=%s remains active across HUP; new connection=new/g2; old stream delivered after-reload event", old[0])
}

func TestNativeConfirmedBootSurvivesLostReceipt(t *testing.T) {
	_, disk, process, auth, compiler := realHarness(t)
	auth.new.Runtime.Now = time.Now().UTC()
	supervisor := edge.NewSupervisor(process, disk, disk, compiler, &lostReceiptAuthority{auth})
	node := domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}
	supervisor.SetBootStore(disk, node)
	if _, err := supervisor.Apply(t.Context(), "new"); err == nil {
		t.Fatal("missing remote receipt hidden")
	}
	reopened, err := fs.New(compiler.root)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := reopened.LoadConfirmed(t.Context(), node)
	if err != nil || bundle.Manifest.Version != "new/g2" {
		t.Fatalf("native confirmation lost: %s %v", bundle.Manifest.Version, err)
	}
	if actual, err := process.Observe(t.Context()); err != nil || actual != bundle.Manifest.Version {
		t.Fatalf("local receipt disagrees with Nginx: %s %v", actual, err)
	}
	route(t)
}

// Seed an initialized test volume using the same native validation/application
// and confirmation path as production. This entry exists only in test binaries.
func TestNativeSeedOfflineFixture(t *testing.T) {
	root := os.Getenv("GATEBEAM_TEST_SEED_BOOT_ROOT")
	if root == "" {
		t.Skip("external restart fixture only")
	}
	disk, err := fs.New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = logfile.InitializeNodeVolume(filepath.Join(root, "logs"), "11111111-1111-4111-8111-111111111111"); err != nil {
		t.Fatal(err)
	}
	process, err := nginx.NewProcess("/usr/sbin/nginx", root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = process.Stop(context.Background()) })
	plan := edge.Plan{Snapshot: app.Snapshot{Version: "offline-v1", Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"route.test"}, Maintenance: app.MaintenancePolicy{Enabled: true, Status: 503, Message: "offline-still-serving"}}}}}, Runtime: edge.RuntimeState{Generation: "g1", Now: time.Now().UTC(), LogDirectory: filepath.Join(root, "logs")}}
	auth := &authority{old: plan, new: plan}
	supervisor := edge.NewSupervisor(process, disk, disk, nginx.Compiler{}, auth)
	supervisor.SetBootStore(disk, domain.NodeRef{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1})
	if _, err = supervisor.Apply(t.Context(), "offline-v1"); err != nil {
		t.Fatal(err)
	}
}
