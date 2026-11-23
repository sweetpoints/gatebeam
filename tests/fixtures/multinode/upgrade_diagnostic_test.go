//go:build integration

package multinode

import (
	"context"
	"errors"
	"gatebeam/internal/platform/lifecycle"
	"net"
	"syscall"
	"testing"
)

func TestUpgradeObservationsExposeOnlyFixedClasses(t *testing.T) {
	const private = "owned-private-transport-or-health-detail"
	for _, row := range []struct {
		err   error
		class string
	}{
		{nil, "none"},
		{errors.Join(errors.New(private), context.DeadlineExceeded), "deadline"},
		{context.Canceled, "cancelled"},
		{&net.OpError{Op: private, Err: syscall.ECONNREFUSED}, "connection-refused"},
		{errFixtureSnapshot, "invalid-status"},
		{errors.New(private), "unclassified"},
	} {
		if observationFailureClass(row.err) != row.class {
			t.Fatal("observation error lost its fixed classification")
		}
	}
	classes := probeClasses(lifecycle.Snapshot{Details: map[string]string{"probe_management": "deadline", "probe_acme": private, private: private}})
	if len(classes) != 7 || classes[lifecycle.Management] != "deadline" || classes[lifecycle.ACME] != "unreported" {
		t.Fatal("probe diagnostics accepted arbitrary health details")
	}
	for key, value := range classes {
		if key == private || value == private {
			t.Fatal("private health detail entered a failure classification")
		}
	}
}
