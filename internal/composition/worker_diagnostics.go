package composition

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/dns"
	"github.com/jackc/pgx/v5/pgconn"
	"io"
	"net"
	"time"
)

type workerStage uint8

const (
	workerSnapshot workerStage = iota
	workerCheck
	workerFlush
)
const workerDiagnosticInterval = time.Minute

type workerDiagnosticEvent struct {
	Component  string `json:"component"`
	Stage      string `json:"stage"`
	Reason     string `json:"reason"`
	Level      string `json:"level"`
	Suppressed uint32 `json:"suppressed,omitempty"`
}
type workerDiagnosticWindow struct {
	emitted    bool
	last       time.Time
	suppressed uint32
}

// Limiter cardinality is exactly the three process-owned stages. Neither error
// text, target identity nor reason changes can create entries or bypass a window.
type workerDiagnostics struct {
	output *json.Encoder
	stages [3]workerDiagnosticWindow
}

func newWorkerDiagnostics(w io.Writer) *workerDiagnostics {
	return &workerDiagnostics{output: json.NewEncoder(w)}
}
func (d *workerDiagnostics) failure(stage workerStage, err error, now time.Time) {
	if err == nil || stage > workerFlush {
		return
	}
	window := &d.stages[stage]
	if window.emitted && now.Sub(window.last) < workerDiagnosticInterval {
		if window.suppressed < ^uint32(0) {
			window.suppressed++
		}
		return
	}
	reason, level := workerReason(stage, err)
	event := workerDiagnosticEvent{Component: "runtime_worker", Stage: [3]string{"snapshot", "check", "flush"}[stage], Reason: reason, Level: level, Suppressed: window.suppressed}
	window.emitted = true
	window.last = now
	window.suppressed = 0
	// The sink is best effort and bounded by the same limiter. Never recurse or
	// substitute a raw error when stderr itself is unavailable.
	_ = d.output.Encode(event)
}
func workerReason(stage workerStage, err error) (string, string) {
	if stage == workerSnapshot && errors.Is(err, domain.ErrNotFound) {
		return "awaiting_publication", "info"
	}
	switch {
	case errors.Is(err, domain.ErrHealthCapacity):
		return "health_capacity", "error"
	case errors.Is(err, domain.ErrUnavailable):
		return "provider_unavailable", "error"
	case errors.Is(err, dns.ErrForbidden):
		return "dns_forbidden", "error"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded", "error"
	case errors.Is(err, context.Canceled):
		return "operation_canceled", "error"
	case errors.Is(err, domain.ErrConflict):
		return "revision_changed", "info"
	}
	var lookup *net.DNSError
	if errors.As(err, &lookup) {
		return "dns_failure", "error"
	}
	var query *pgconn.PgError
	var connection *pgconn.ConnectError
	if errors.As(err, &query) || errors.As(err, &connection) {
		return "database_failure", "error"
	}
	return [3]string{"snapshot_unavailable", "check_failed", "generation_enqueue_failed"}[stage], "error"
}
