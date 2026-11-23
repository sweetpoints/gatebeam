package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/dns"
	"github.com/jackc/pgx/v5/pgconn"
	"net"
	"strings"
	"testing"
	"time"
)

// Error text is untrusted: even asking for it is a diagnostic contract failure.
type sensitiveWorkerError struct{}

func (sensitiveWorkerError) Error() string { panic("raw DSN/query/credential error text read") }

type diagnosticRuntime struct {
	snapshot              app.Snapshot
	snapshotErr, flushErr error
	snapshots, flushes    int
}

func (r *diagnosticRuntime) Snapshot(context.Context) (app.Snapshot, error) {
	r.snapshots++
	return r.snapshot, r.snapshotErr
}
func (r *diagnosticRuntime) Flush(context.Context) error { r.flushes++; return r.flushErr }

type diagnosticCheck struct {
	err    error
	calls  int
	cancel context.CancelFunc
}

func (c *diagnosticCheck) Check(context.Context, string, int64) (health.Transition, error) {
	c.calls++
	if c.cancel != nil {
		c.cancel()
	}
	return health.Transition{}, c.err
}
func diagnosticFixture(t *testing.T) (*workerLoop, *diagnosticRuntime, *diagnosticCheck, *bytes.Buffer, *time.Time) {
	t.Helper()
	now := time.Unix(1000, 0)
	output := &bytes.Buffer{}
	repo := &diagnosticRuntime{snapshot: app.Snapshot{Version: "published", Targets: []app.Target{{ID: "secret-id-must-not-be-error-message", Revision: 1}}}}
	check := &diagnosticCheck{}
	return newWorkerLoop(repo, check, newWorkerDiagnostics(output), func() time.Time { return now }), repo, check, output, &now
}
func decodeWorkerEvents(t *testing.T, b *bytes.Buffer) []workerDiagnosticEvent {
	t.Helper()
	out := []workerDiagnosticEvent{}
	decoder := json.NewDecoder(strings.NewReader(b.String()))
	for decoder.More() {
		var v workerDiagnosticEvent
		if e := decoder.Decode(&v); e != nil {
			t.Fatal(e)
		}
		out = append(out, v)
	}
	return out
}
func TestWorkerDiagnosticsObserveAllStagesWithoutStopping(t *testing.T) {
	worker, repo, check, out, now := diagnosticFixture(t)
	repo.snapshotErr = sensitiveWorkerError{}
	repo.flushErr = sensitiveWorkerError{}
	worker.step(context.Background())
	repo.snapshotErr = nil
	repo.flushErr = nil
	check.err = domain.ErrUnavailable
	*now = now.Add(2 * time.Second)
	worker.step(context.Background())
	check.err = nil
	*now = now.Add(10 * time.Second)
	worker.step(context.Background())
	events := decodeWorkerEvents(t, out)
	if len(events) != 3 || events[0].Stage != "snapshot" || events[0].Reason != "snapshot_unavailable" || events[1].Stage != "flush" || events[1].Reason != "generation_enqueue_failed" || events[2].Stage != "check" || events[2].Reason != "provider_unavailable" {
		t.Fatal(events)
	}
	if repo.snapshots != 3 || repo.flushes != 3 || check.calls != 2 {
		t.Fatal("worker stopped on failure", repo, check)
	}
	if strings.Contains(out.String(), "secret-id") || strings.Contains(out.String(), "DSN") {
		t.Fatal("untrusted error/resource data leaked", out.String())
	}
}
func TestWorkerDiagnosticsBoundRecurringErrorsAndSuppression(t *testing.T) {
	worker, repo, _, out, now := diagnosticFixture(t)
	repo.snapshotErr = sensitiveWorkerError{}
	for i := 0; i < 100; i++ {
		worker.step(context.Background())
	}
	if got := decodeWorkerEvents(t, out); len(got) != 1 {
		t.Fatal("recurring errors unbounded", len(got))
	}
	*now = now.Add(time.Minute)
	worker.step(context.Background())
	got := decodeWorkerEvents(t, out)
	if len(got) != 2 || got[1].Suppressed != 99 {
		t.Fatal("suppression count missing", got)
	}
	if len(worker.diagnostics.stages) != 3 {
		t.Fatal("limiter state is not fixed by three known stages")
	}
}
func TestWorkerDiagnosticsDistinguishInitialPublicationAndShutdown(t *testing.T) {
	worker, repo, check, out, now := diagnosticFixture(t)
	repo.snapshotErr = domain.ErrNotFound
	worker.step(context.Background())
	got := decodeWorkerEvents(t, out)
	if len(got) != 1 || got[0].Reason != "awaiting_publication" || got[0].Level != "info" {
		t.Fatal(got)
	}
	repo.snapshotErr = nil
	check.err = context.Canceled
	ctx, cancel := context.WithCancel(context.Background())
	check.cancel = cancel
	*now = now.Add(time.Minute)
	worker.step(ctx)
	if len(decodeWorkerEvents(t, out)) != 1 || repo.flushes != 1 {
		t.Fatal("normal shutdown logged or continued work", out.String(), repo.flushes)
	}
}
func TestWorkerDiagnosticReasonsAreFixedForTypedFailures(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{{domain.ErrHealthCapacity, "health_capacity"}, {domain.ErrUnavailable, "provider_unavailable"}, {context.DeadlineExceeded, "deadline_exceeded"}, {domain.ErrConflict, "revision_changed"}, {sensitiveWorkerError{}, "check_failed"}, {dns.ErrForbidden, "dns_forbidden"}, {&net.DNSError{Err: "postgres://secret-user:secret-password@private-host", Name: "secret-id"}, "dns_failure"}, {&pgconn.PgError{Message: "secret query and credentials", Detail: "private key detail"}, "database_failure"}} {
		var out bytes.Buffer
		newWorkerDiagnostics(&out).failure(workerCheck, tc.err, time.Unix(1, 0))
		events := decodeWorkerEvents(t, &out)
		if len(events) != 1 || events[0].Reason != tc.reason {
			t.Fatal(tc.reason, events)
		}
		if strings.Contains(out.String(), "secret") || strings.Contains(out.String(), "private key") {
			t.Fatal("typed error details leaked", out.String())
		}
	}
	var out bytes.Buffer
	newWorkerDiagnostics(&out).failure(workerCheck, errors.Join(context.Canceled, sensitiveWorkerError{}), time.Unix(1, 0))
	events := decodeWorkerEvents(t, &out)
	if len(events) != 1 || events[0].Reason != "operation_canceled" {
		t.Fatal("unexpected operation cancellation silently discarded", events)
	}
}

func TestWorkerDiagnosticWindowSurvivesRecoveryFlapping(t *testing.T) {
	worker, repo, _, out, now := diagnosticFixture(t)
	for i := 0; i < 20; i++ {
		if i%2 == 0 {
			repo.snapshotErr = sensitiveWorkerError{}
		} else {
			repo.snapshotErr = nil
		}
		worker.step(context.Background())
		*now = now.Add(time.Second)
	}
	events := decodeWorkerEvents(t, out)
	if len(events) != 1 {
		t.Fatal("recovery reset the stage limit", events)
	}
	*now = now.Add(time.Minute)
	repo.snapshotErr = sensitiveWorkerError{}
	worker.step(context.Background())
	events = decodeWorkerEvents(t, out)
	if len(events) != 2 || events[1].Suppressed != 9 {
		t.Fatal("flapping suppression summary lost", events)
	}
}

func TestWorkerDiagnosticReasonChangesCannotExpandLimit(t *testing.T) {
	var output bytes.Buffer
	diagnostics := newWorkerDiagnostics(&output)
	now := time.Unix(1, 0)
	for _, err := range []error{domain.ErrHealthCapacity, domain.ErrUnavailable, &net.DNSError{Err: "private-id-as-error", Name: "secret-network"}, sensitiveWorkerError{}} {
		diagnostics.failure(workerCheck, err, now)
	}
	events := decodeWorkerEvents(t, &output)
	if len(events) != 1 || events[0].Reason != "health_capacity" {
		t.Fatal("new error causes bypassed fixed-stage rate bound", events)
	}
	diagnostics.failure(workerCheck, domain.ErrUnavailable, now.Add(time.Minute))
	events = decodeWorkerEvents(t, &output)
	if len(events) != 2 || events[1].Reason != "provider_unavailable" || events[1].Suppressed != 3 {
		t.Fatal(events)
	}
	if strings.Contains(output.String(), "secret") || strings.Contains(output.String(), "private-id") {
		t.Fatal("untrusted field leaked", output.String())
	}
}
