//go:build integration

package multinode_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"gatebeam/internal/modules/deployment/application/upgrade"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/lifecycle"
	fixture "gatebeam/tests/fixtures/multinode"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func upgradePlan(t testing.TB, l *fixture.Lab, id, executor, scope, image string) upgrade.Plan {
	t.Helper()
	i := upgrade.Inventory{Schema: 27, RoleSchema: 7, Compatible: true}
	for _, n := range l.Nodes {
		i.Nodes = append(i.Nodes, n.Info)
	}
	r := upgrade.Request{BatchID: id, ExecutorInstance: executor, Scope: scope, DrainSeconds: 1, ObserveSeconds: 1}
	if scope == "role" {
		r.Role = "management"
		r.Images = map[string]string{"management": image}
	}
	p, e := upgrade.BuildPlan(r, i)
	if e != nil {
		t.Fatal(e)
	}
	return p
}
func TestWholeNodeMaintenanceRetainsOfflineBoot(t *testing.T) {
	l := fixture.Start(t)
	business := l.Business(t)
	ops := fixture.NewUpgradeOperations(t, l)
	executor := "projects/owned/zones/us-west1-c/instances/maintenance"
	p := upgradePlan(t, l, "55555555-5555-4555-8555-555555555555", executor, "host", "")
	pids := map[string]map[string]string{}
	for _, n := range l.Nodes {
		pids[n.Info.Node.ID] = map[string]string{}
		for role := range fixture.Modes {
			id := n.Compose(t, "ps", "-q", role)
			pids[n.Info.Node.ID][role] = fixture.Docker(t, "inspect", "--format", "{{.State.Pid}}", id)
		}
	}
	var active atomic.Int32
	var requests, failures atomic.Int64
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			n := l.Nodes[active.Load()]
			r, e := business.Clients[n.Info.Node.ID].Get("https://service.dual.test/")
			requests.Add(1)
			if e != nil {
				failures.Add(1)
			} else {
				body, readErr := io.ReadAll(io.LimitReader(r.Body, 1024))
				r.Body.Close()
				if r.StatusCode != 200 || readErr != nil || string(body) != "owned-business" {
					failures.Add(1)
				}
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	type streamEnd struct {
		ContextErr error
		ClosedAt   time.Time
	}
	streamClosed := make(chan streamEnd, 1)
	streamObserved := false
	var drainDeadline time.Time
	// Open a fresh stream immediately before the actual owned Nginx drain,
	// after unrelated prechecks and management-route preparation have finished.
	ops.BeforeDrain = func(step upgrade.Step, role string) {
		if role != "nginx" || step.Node.ID != l.Nodes[0].Info.Node.ID {
			return
		}
		sseCtx, sseCancel := context.WithCancel(t.Context())
		t.Cleanup(sseCancel)
		establish := time.AfterFunc(10*time.Second, sseCancel)
		defer establish.Stop()
		base := business.Clients[l.Nodes[0].Info.Node.ID]
		sseClient := &http.Client{Transport: base.Transport}
		req, _ := http.NewRequestWithContext(sseCtx, "GET", "https://service.dual.test/events", nil)
		stream, err := sseClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stream.Body.Close() })
		reader := bufio.NewReader(stream.Body)
		if line, err := reader.ReadString('\n'); err != nil || !strings.HasPrefix(line, "data:") {
			t.Fatal("no SSE before actual drain", err)
		}
		if !establish.Stop() {
			t.Fatal("SSE establishment exceeded its unchanged deadline")
		}
		go func() {
			for {
				if _, err := reader.ReadString('\n'); err != nil {
					streamClosed <- streamEnd{ContextErr: sseCtx.Err(), ClosedAt: time.Now()}
					return
				}
			}
		}()
	}
	ops.AfterDrain = func(step upgrade.Step, role string, deadline time.Time) {
		if role == "nginx" && step.Node.ID == l.Nodes[0].Info.Node.ID {
			drainDeadline = deadline
		}
	}
	ops.AfterApply = func(step upgrade.Step) {
		if step.Kind == "public-remove" {
			if step.Node.ID == l.Nodes[0].Info.Node.ID {
				active.Store(1)
			} else {
				active.Store(0)
			}
		}
		if step.Kind != "host-stop" || step.Node.ID != l.Nodes[0].Info.Node.ID {
			return
		}
		if drainDeadline.IsZero() {
			t.Fatal("actual owned drain receipt missing")
		}
		// Existing streams may end during drain or the bounded native stop.
		// Keep the original one-second observation allowance after that actual
		// stop, rather than after unrelated work on the other gateway.
		cutoff := time.Now().Add(time.Second)
		var end streamEnd
		select {
		case end = <-streamClosed:
		default:
			timer := time.NewTimer(time.Until(cutoff))
			defer timer.Stop()
			select {
			case end = <-streamClosed:
			case <-timer.C:
				t.Fatal("SSE not disconnected at finite native maintenance")
			}
		}
		if end.ContextErr != nil {
			t.Fatal("SSE ended through client cancellation")
		}
		if end.ClosedAt.Before(drainDeadline.Add(-time.Second)) {
			t.Fatal("SSE disconnected before actual native drain began")
		}
		if end.ClosedAt.After(cutoff) {
			t.Fatal("SSE survived the bounded native stop")
		}
		streamObserved = true
	}
	x := upgrade.Executor{Store: ops.Store, Operations: ops, ExecutorInstance: executor}
	if e := x.Run(t.Context(), p); e != nil {
		if run, loadErr := ops.Store.Load(t.Context(), p.ID); loadErr == nil && run.Next < len(run.Plan.Steps) {
			t.Logf("owned whole-node upgrade stopped: state=%s step=%s", run.State, run.Plan.Steps[run.Next].Kind)
		}
		t.Fatal(e)
	}
	cancel()
	<-done
	if requests.Load() < 5 || failures.Load() != 0 {
		t.Fatal("healthy node lost new requests", requests.Load(), failures.Load())
	}
	if !streamObserved {
		t.Fatal("actual owned Nginx drain was not observed")
	}
	for _, n := range l.Nodes {
		for role, old := range pids[n.Info.Node.ID] {
			id := n.Compose(t, "ps", "-q", role)
			now := fixture.Docker(t, "inspect", "--format", "{{.State.Pid}}", id)
			if old == now || now == "0" {
				t.Fatal("role process not replaced", role)
			}
		}
	}
	db := os.Getenv("GATEBEAM_TEST_DB_CONTAINER")
	fixture.Docker(t, "network", "disconnect", l.Network, db)
	for _, n := range l.Nodes {
		n.Compose(t, "stop", "--timeout", "2", "management", "background-jobs", "log-query")
	}
	for _, n := range l.Nodes {
		fixture.Docker(t, "network", "disconnect", n.Info.StoragePrefix+"_node-private", n.Router)
		fixture.Docker(t, "network", "disconnect", n.Info.StoragePrefix+"_query-egress", n.Router)
		n.Compose(t, "down", "--remove-orphans", "--timeout", "2")
		n.Compose(t, "create", "--no-build")
		addr, _ := netip.ParseAddrPort(n.Configs["nginx"].HealthListen)
		query, _ := netip.ParseAddrPort(n.Configs["log-query"].HealthListen)
		fixture.Docker(t, "network", "connect", "--ip", addr.Addr().Next().Next().String(), n.Info.StoragePrefix+"_node-private", n.Router)
		fixture.Docker(t, "network", "connect", "--ip", query.Addr().Next().String(), n.Info.StoragePrefix+"_query-egress", n.Router)
		n.RefreshPorts(t)
		n.Compose(t, "start", "nginx")
		n.Wait(t, "nginx", lifecycle.Data)
		n.RefreshClients(t, l.Trust)
		business.RefreshClient(t, n)
		if business.Get(t, n, "/") != 200 {
			t.Fatal("whole retained node failed offline boot")
		}
	}
	fixture.Docker(t, "network", "connect", "--alias", "database", l.Network, db)
	for _, n := range l.Nodes {
		n.Compose(t, "start", "management", "background-jobs", "log-query")
		n.Wait(t, "management", lifecycle.Management)
	}
	t.Logf("four gateway processes restarted per node; %d new TLS requests, %d errors; SSE terminated; both node groups/networks recreated offline with retained volumes, no kernel reboot claim", requests.Load(), failures.Load())
}

type executorInput struct {
	DSN          string
	Nodes        []*fixture.Node
	Network, Run string
	Plan         upgrade.Plan
	Images       map[string]string
	Signal       string
}

func TestOwnedExecutorChild(t *testing.T) {
	path := os.Getenv("GATEBEAM_OWNED_EXECUTOR_INPUT")
	if path == "" {
		t.Skip("owned subprocess only")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("owned child input")
	}
	var in executorInput
	if json.Unmarshal(raw, &in) != nil {
		t.Fatal("owned child decode")
	}
	pool, e := pgxpool.New(t.Context(), in.DSN)
	if e != nil {
		t.Fatal("owned child DB")
	}
	defer pool.Close()
	l := &fixture.Lab{Pool: pool, Nodes: in.Nodes, Network: in.Network, Run: in.Run}
	// Parent already prepared business/canary state. This child only reaches
	// the post-update interruption cut; do not create fresh sites or sessions.
	ops := &fixture.UpgradeOperations{T: t, Lab: l, Store: repo.UpgradeStore{Pool: pool}, Images: in.Images, Public: map[string]bool{}, Private: map[string]bool{}}
	for _, n := range l.Nodes {
		ops.Public[n.Info.Node.ID] = true
		ops.Private[n.Info.Node.ID] = true
	}
	ops.CrashAfterApply = "update"
	ops.CrashSignal = in.Signal
	started := time.Now()
	ops.AfterApply = func(s upgrade.Step) {
		t.Logf("owned executor applied step=%s elapsed=%s", s.Kind, time.Since(started).Round(time.Millisecond))
	}
	x := upgrade.Executor{Store: ops.Store, Operations: ops, ExecutorInstance: in.Plan.ExecutorInstance}
	// The publication receipt does not wait for the edge's periodic data
	// readiness check. Establish this fixture prerequisite before the executor's
	// one-shot upgrade precheck so the test can exercise the interruption cut.
	for _, n := range l.Nodes {
		n.Wait(t, "nginx", lifecycle.Data)
	}
	t.Log("owned executor starting real upgrade before fault injection")
	err := x.Run(t.Context(), in.Plan)
	t.Fatal("child stopped before post-effect cut", err)
}
func ownedImage(t testing.TB, l *fixture.Lab, bad bool) string {
	t.Helper()
	dir := t.TempDir()
	tag := fmt.Sprintf("gatebeam-owned-image:%d", time.Now().UnixNano())
	source := "FROM gatebeam-api:local\nLABEL gatebeam.fixture=\"" + tag + "\"\n"
	if bad {
		source += "ENTRYPOINT [\"/usr/local/bin/gatebeam\",\"--runtime-contract\"]\n"
	}
	if os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(source), 0600) != nil {
		t.Fatal("image fixture")
	}
	fixture.Docker(t, "build", "--network", "none", "-t", tag, dir)
	t.Cleanup(func() {
		for _, n := range l.Nodes {
			fixture.CleanupDocker(t, "compose", "-p", n.Info.StoragePrefix, "-f", n.ComposeFile, "rm", "-sf", "management")
		}
		fixture.CleanupDocker(t, "image", "rm", tag)
	})
	return tag
}
func TestExecutorProcessInterruptionAndRejectedVersion(t *testing.T) {
	l := fixture.Start(t)
	business := l.Business(t)
	ops := fixture.NewUpgradeOperations(t, l)
	good := ownedImage(t, l, false)
	bad := ownedImage(t, l, true)
	desired := "registry.example/gatebeam/api@" + fixture.Docker(t, "image", "inspect", good, "--format", "{{.Id}}")
	broken := "registry.example/gatebeam/api@" + fixture.Docker(t, "image", "inspect", bad, "--format", "{{.Id}}")
	ops.Images[desired] = good
	ops.Images[broken] = bad
	for _, n := range l.Nodes {
		ops.Images[n.Info.Roles["management"].Image] = "gatebeam-api:local"
	}
	oldExecutor := "projects/owned/zones/us-west1-c/instances/executor-old"
	nextExecutor := "projects/owned/zones/us-west1-c/instances/executor-next"
	p := upgradePlan(t, l, "66666666-6666-4666-8666-666666666666", oldExecutor, "role", desired)
	bID := l.Nodes[1].Compose(t, "ps", "-q", "management")
	signal := filepath.Join(t.TempDir(), "cut")
	dbURL, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	params := dbURL.Query()
	params.Set("search_path", l.Pool.Config().ConnConfig.RuntimeParams["search_path"])
	dbURL.RawQuery = params.Encode()
	in := executorInput{DSN: dbURL.String(), Nodes: l.Nodes, Network: l.Network, Run: l.Run, Plan: p, Images: ops.Images, Signal: signal}
	raw, e := json.Marshal(in)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "child.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	executable, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	cmd := exec.CommandContext(t.Context(), executable, "-test.run=^TestOwnedExecutorChild$", "-test.v")
	cmd.Env = append(os.Environ(), "GATEBEAM_OWNED_EXECUTOR_INPUT="+path)
	childLog, e := os.CreateTemp(t.TempDir(), "executor-log-")
	if e != nil {
		t.Fatal(e)
	}
	defer childLog.Close()
	cmd.Stdout, cmd.Stderr = childLog, childLog
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	// This observer prepares the fault: the child must perform the real upgrade
	// up to the post-update cut before any interruption/recovery assertion starts.
	// Individual drain, control, verification and Docker deadlines remain intact.
	cutBudget := 12 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		cutBudget *= 12
	}
	cutStarted := time.Now()
	end := cutStarted.Add(cutBudget)
	parked := false
	for time.Now().Before(end) {
		if _, e = os.Stat(signal + ".ready"); e == nil {
			parked = true
			break
		}
		time.Sleep(30 * time.Millisecond)
	}
	if !parked {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if _, e = childLog.Seek(0, io.SeekStart); e != nil {
			t.Fatal(e)
		}
		diagnostic, _ := io.ReadAll(io.LimitReader(childLog, 16384))
		t.Fatalf("child never reached actual post-update boundary after %s (budget %s): %s", time.Since(cutStarted).Round(time.Millisecond), cutBudget, diagnostic)
	}
	t.Logf("owned executor reached actual post-update boundary in %s", time.Since(cutStarted).Round(time.Millisecond))
	run, e := ops.Store.Load(t.Context(), p.ID)
	if e != nil || run.Pending == nil || run.Operation != nil {
		t.Fatal("durable pending intent missing", e)
	}
	ops.Calls = append(ops.Calls, *run.Pending)
	proof := upgrade.RecoveryProof{BatchID: p.ID, PreviousExecutor: oldExecutor, Revision: run.Revision, Operations: []upgrade.OperationRef{{StepID: run.Pending.ID, HostCommandID: run.Pending.ID}}}
	x := upgrade.Executor{Store: repo.UpgradeStore{Pool: l.Pool}, Operations: ops, ExecutorInstance: nextExecutor}
	if e = x.Resume(t.Context(), p.ID, proof); e == nil {
		t.Fatal("live child executor replaced")
	}
	if bID != l.Nodes[1].Compose(t, "ps", "-q", "management") {
		t.Fatal("B touched while A unverified")
	}
	if e = os.WriteFile(signal+".exit", []byte("owned"), 0600); e != nil {
		t.Fatal(e)
	}
	e = cmd.Wait()
	var exit *exec.ExitError
	if !errors.As(e, &exit) || exit.ExitCode() != 77 {
		t.Fatal("expected real executor exit77", e)
	}
	ops.ExecutorExited = cmd.ProcessState
	if e = x.Resume(t.Context(), p.ID, proof); e != nil {
		t.Fatal("fenced post-effect recovery", e)
	}
	bID = l.Nodes[1].Compose(t, "ps", "-q", "management")
	p = upgradePlan(t, l, "77777777-7777-4777-8777-777777777777", nextExecutor, "role", broken)
	if e = x.Run(t.Context(), p); !errors.Is(e, upgrade.ErrRolledBack) {
		t.Fatal("bad version not rejected and restored", e)
	}
	if bID != l.Nodes[1].Compose(t, "ps", "-q", "management") {
		t.Fatal("bad A caused B replacement")
	}
	for _, n := range l.Nodes {
		if business.Get(t, n, "/") != 200 {
			t.Fatal("upgrade failure interrupted business")
		}
	}
	t.Log("real child stayed alive/rejected takeover, exited77 after container update before receipt, parent verified actual effect and resumed; rejected image restored A only; B retained")
}
