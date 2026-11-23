//go:build integration

package multinode

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

func TestControlFailureRetainsOnlyFixedClassifications(t *testing.T) {
	for _, cause := range []string{"capability", "archive", "query"} {
		message := "owned control rejected: path=/capabilities/verify status=503 body_read_error=false cause=" + cause + "\n"
		err := controlCommandFailure("background-jobs", "/capabilities/verify", t.Context(), &exec.ExitError{Stderr: []byte(message)})
		if !strings.Contains(err.Error(), "status=503 cause="+cause) {
			t.Error("fixed capability failure classification lost")
		}
	}
	const marker = "owned-private-response-marker"
	err := controlCommandFailure("background-jobs", "/capabilities/verify", context.Background(), &exec.ExitError{Stderr: []byte(marker)})
	if strings.Contains(err.Error(), marker) {
		t.Error("raw CLI stderr entered diagnostics")
	}
	if controlCause([]byte(marker)) != "unclassified" {
		t.Error("arbitrary response body accepted as a fixed classification")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !strings.Contains(controlCommandFailure("background-jobs", "/capabilities/verify", ctx, context.Canceled).Error(), "deadline_expired=false context_cancelled=true") {
		t.Error("transport cancellation classification lost")
	}
}

func TestPreviewFailureRetainsOnlyReportedClasses(t *testing.T) {
	const private = "owned-private-database-and-material-path"
	for _, row := range []struct{ stderr, want string }{
		{private + ": context deadline exceeded", "deadline-reported"},
		{private + ": permission denied", "permission-reported"},
		{private, "stderr-unclassified"},
		{private + "\ngatebeam enrollment preview phase=source-read elapsed_ms=20005 deadline_expired=true context_cancelled=false\n", "preview-phase=source-read elapsed_ms=20005 deadline_expired=true context_cancelled=false"},
		{"gatebeam enrollment preview phase=" + private + " elapsed_ms=20005 deadline_expired=true context_cancelled=false", "stderr-unclassified"},
	} {
		class := previewFailureClass(&exec.ExitError{Stderr: []byte(row.stderr)})
		if class != row.want || strings.Contains(class, private) {
			t.Fatal("preview diagnostic lost its fixed classification or disclosed stderr")
		}
	}
	if previewFailureClass(context.Canceled) != "executor-unclassified" {
		t.Fatal("non-CLI failure was misclassified as reported stderr")
	}
}

func TestQueryFailureLogFilteringNeverCopiesRawRoleLogs(t *testing.T) {
	const private = "owned-private-role-log-material"
	raw := private + "\nworker | gatebeam query capability failure class=timeout elapsed_ms=5000 deadline_expired=true database_ms=100 history_ms=200 archive_ms=300 query_ms=4400\n" +
		"worker | gatebeam query capability failure class=" + private + " elapsed_ms=5000 deadline_expired=true database_ms=100 history_ms=200 archive_ms=300 query_ms=4400\n" +
		"worker | gatebeam query capability failure class=failed elapsed_ms=5000 deadline_expired=false database_ms=100 history_ms=200 archive_ms=300 query_ms=4400 " + private + "\n" +
		"query | gatebeam query child failure prepare_ms=4 child_ms=4396 deadline_expired=true context_cancelled=false\n" +
		"query | gatebeam query child failure prepare_ms=4 child_ms=4396 deadline_expired=true context_cancelled=false " + private + "\n" +
		"query | gatebeam query phase failure phase=extension phase_ms=4100 cli_ms=200 extension_loaded_ms=0 query_started_ms=0\n" +
		"query | gatebeam query phase failure phase=" + private + " phase_ms=4100 cli_ms=200 extension_loaded_ms=0 query_started_ms=0\n" +
		"query | gatebeam query phase failure phase=query phase_ms=4100 cli_ms=200 extension_loaded_ms=300 query_started_ms=400 " + private + "\n"
	lines := classifiedQueryFailureLogs([]byte(raw))
	if len(lines) != 3 || lines[1] != "query child failure: prepare_ms=4 child_ms=4396 deadline_expired=true context_cancelled=false" || lines[0] != "query capability failure: class=timeout elapsed_ms=5000 deadline_expired=true database_ms=100 history_ms=200 archive_ms=300 query_ms=4400" || lines[2] != "query phase failure: phase=extension phase_ms=4100 cli_ms=200 extension_loaded_ms=0 query_started_ms=0" || strings.Contains(strings.Join(lines, ""), private) {
		t.Fatal("raw role logs bypassed the fixed query failure filter")
	}
}
