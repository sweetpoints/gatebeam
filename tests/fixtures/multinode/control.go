//go:build integration

package multinode

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// OwnerControl is test-only transport to the production owner Unix routes.
func OwnerControl(raw string) ([]byte, error) {
	var command struct {
		Path string
		Body json.RawMessage
	}
	if json.Unmarshal([]byte(raw), &command) != nil || !strings.HasPrefix(command.Path, "/") {
		return nil, errors.New("invalid owned command")
	}
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", "/run/control/control.sock")
	}}}
	r, e := client.Post("http://owner"+command.Path, "application/json", bytes.NewReader(command.Body))
	if e != nil {
		return nil, e
	}
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
	if e != nil || r.StatusCode < 200 || r.StatusCode >= 300 {
		return nil, fmt.Errorf("owned control rejected: path=%s status=%d body_read_error=%t cause=%s", command.Path, r.StatusCode, e != nil, controlCause(b))
	}
	if len(b) == 0 {
		b = []byte(`{}`)
	}
	return b, nil
}

// Keep only fixed owner classifications; response bodies and CLI stderr may
// contain credentials or operation inputs and must never enter diagnostics.
func controlCause(body []byte) string {
	switch strings.TrimSpace(string(body)) {
	case "capability unavailable":
		return "capability"
	case "archive capability unavailable":
		return "archive"
	case "query capability unavailable":
		return "query"
	case "invalid command":
		return "invalid-command"
	default:
		return "unclassified"
	}
}

func controlCommandFailure(role, path string, ctx context.Context, err error) error {
	status, cause := 0, "transport-or-executor"
	readError := false
	var exit *exec.ExitError
	if errors.As(err, &exit) && bytes.HasPrefix(exit.Stderr, []byte("owned control rejected: path="+path+" ")) {
		for _, code := range []int{400, 401, 403, 404, 409, 500, 503} {
			if bytes.Contains(exit.Stderr, []byte("status="+strconv.Itoa(code)+" ")) {
				status = code
			}
		}
		cause = "unclassified"
		for _, name := range []string{"capability", "archive", "query", "invalid-command"} {
			if strings.TrimSpace(string(exit.Stderr)) == fmt.Sprintf("owned control rejected: path=%s status=%d body_read_error=false cause=%s", path, status, name) {
				cause = name
			}
		}
		readError = bytes.Contains(exit.Stderr, []byte("body_read_error=true "))
	}
	return fmt.Errorf("owned control failed: role=%s path=%s status=%d cause=%s body_read_error=%t deadline_expired=%t context_cancelled=%t", role, path, status, cause, readError, errors.Is(ctx.Err(), context.DeadlineExceeded), errors.Is(ctx.Err(), context.Canceled))
}
var previewMetadataLine = regexp.MustCompile(`gatebeam enrollment preview phase=(configuration|database-open|certificate-reader|distribution|status-profile|artifact-read|source-read|compile|transaction-commit) elapsed_ms=([0-9]{1,9}) deadline_expired=(true|false) context_cancelled=(true|false)$`)

// Preview stderr may contain database addresses or private material paths.
// Retain only fixed reported classes; these never change acceptance decisions.
func previewFailureClass(err error) string {
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		return "executor-unclassified"
	}
	for _, line := range bytes.Split(exit.Stderr, []byte("\n")) {
		if fields := previewMetadataLine.FindSubmatch(line); fields != nil {
			return fmt.Sprintf("preview-phase=%s elapsed_ms=%s deadline_expired=%s context_cancelled=%s", fields[1], fields[2], fields[3], fields[4])
		}
	}
	for _, item := range []struct{ text, class string }{
		{"context deadline exceeded", "deadline-reported"},
		{"permission denied", "permission-reported"},
		{"no such file or directory", "missing-file-reported"},
		{"connection refused", "connection-refused-reported"},
		{"failed to connect", "connection-reported"},
		{"i/o timeout", "network-timeout-reported"},
		{"management bootstrap material unavailable", "management-material-reported"},
		{"invalid management bootstrap material", "invalid-management-material-reported"},
		{"current runtime scope unavailable", "runtime-scope-reported"},
		{"process capability", "capability-reported"},
	} {
		if bytes.Contains(exit.Stderr, []byte(item.text)) {
			return item.class
		}
	}
	return "stderr-unclassified"
}

func (n *Node) Control(t testing.TB, role, path string, body any) []byte {
	t.Helper()
	raw, e := json.Marshal(map[string]any{"Path": path, "Body": body})
	if e != nil {
		t.Fatal(e)
	}
	id := n.Compose(t, "ps", "-q", role)
	return []byte(Docker(t, "exec", "-e", "GATEBEAM_TEST_OWNER_CONTROL="+string(raw), id, "/capabilities"))
}

func FsyncLogs() error {
	entries, e := os.ReadDir("/var/lib/gatebeam/logs")
	if e != nil {
		return e
	}
	for _, v := range entries {
		if strings.HasSuffix(v.Name(), ".log") {
			f, e := os.Open(filepath.Join("/var/lib/gatebeam/logs", v.Name()))
			if e != nil {
				return e
			}
			e = f.Sync()
			f.Close()
			if e != nil {
				return e
			}
		}
	}
	return nil
}

func (n *Node) TryControl(t testing.TB, role, path string, body any) ([]byte, error) {
	t.Helper()
	raw, e := json.Marshal(map[string]any{"Path": path, "Body": body})
	if e != nil {
		return nil, e
	}
	id := n.Compose(t, "ps", "-q", role)
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "docker", "exec", "-e", "GATEBEAM_TEST_OWNER_CONTROL="+string(raw), id, "/capabilities").Output()
	if err != nil {
		return nil, controlCommandFailure(role, path, ctx, err)
	}
	return out, nil
}

var queryFailureLine = regexp.MustCompile(`gatebeam query capability failure class=(deadline|cancelled|timeout|busy|missing-object|incomplete|invalid|capacity|unavailable|failed) elapsed_ms=([0-9]{1,9}) deadline_expired=(true|false) database_ms=([0-9]{1,9}) history_ms=([0-9]{1,9}) archive_ms=([0-9]{1,9}) query_ms=([0-9]{1,9})$`)

var queryChildFailureLine = regexp.MustCompile(`gatebeam query child failure prepare_ms=([0-9]{1,9}) child_ms=([0-9]{1,9}) deadline_expired=(true|false) context_cancelled=(true|false)$`)

var queryPhaseFailureLine = regexp.MustCompile(`gatebeam query phase failure phase=(startup|configuration|extension|settings|query) phase_ms=([0-9]{1,9}) cli_ms=([0-9]{1,9}) extension_loaded_ms=([0-9]{1,9}) query_started_ms=([0-9]{1,9})$`)

func classifiedQueryFailureLogs(raw []byte) []string {
	var out []string
	for _, line := range bytes.Split(raw, []byte("\n")) {
		fields := queryFailureLine.FindSubmatch(line)
		if fields != nil {
			out = append(out, fmt.Sprintf("query capability failure: class=%s elapsed_ms=%s deadline_expired=%s database_ms=%s history_ms=%s archive_ms=%s query_ms=%s", fields[1], fields[2], fields[3], fields[4], fields[5], fields[6], fields[7]))
		}
		child := queryChildFailureLine.FindSubmatch(line)
		if child != nil {
			out = append(out, fmt.Sprintf("query child failure: prepare_ms=%s child_ms=%s deadline_expired=%s context_cancelled=%s", child[1], child[2], child[3], child[4]))
		}
		phase := queryPhaseFailureLine.FindSubmatch(line)
		if phase != nil {
			out = append(out, fmt.Sprintf("query phase failure: phase=%s phase_ms=%s cli_ms=%s extension_loaded_ms=%s query_started_ms=%s", phase[1], phase[2], phase[3], phase[4], phase[5]))
		}
	}
	return out
}

// Called only after a test has already decided to fail. It neither retries
// the canary nor changes readiness, and raw role logs never enter the receipt.
func (n *Node) LogQueryCapabilityFailure(t testing.TB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), cleanupBudget(3*time.Second))
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", "compose", "-p", n.Info.StoragePrefix, "-f", n.ComposeFile, "logs", "--no-color", "--tail", "8", "background-jobs", "log-query").CombinedOutput()
	if err != nil {
		t.Log("classified query capability failure logs unavailable")
		return
	}
	classes := classifiedQueryFailureLogs(raw)
	if len(classes) == 0 {
		t.Log("no classified query capability failure log")
	}
	for _, line := range classes {
		t.Log(line)
	}
}
