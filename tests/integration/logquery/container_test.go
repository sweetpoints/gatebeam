//go:build integration

package logquery_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"gatebeam/internal/modules/observability/domain"
	objectstore "gatebeam/internal/modules/observability/infrastructure/s3"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func docker(t *testing.T, input []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(input)
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("owned container operation failed: %v %s", e, out)
	}
	return out
}
func TestProductionQueryWorkerContainer(t *testing.T) {
	_, _, m, _ := fixture(t)
	network := os.Getenv("GATEBEAM_TEST_NETWORK")
	if network == "" {
		t.Fatal("owned query network required")
	}
	name := fmt.Sprintf("gatebeam-o2-query-%d", time.Now().UnixNano())
	volume := name + "-socket"
	dir := t.TempDir()
	cfg := map[string]string{"mode": "query", "environment": "production", "query_credentials_file": "/run/gatebeam/r2.json", "query_socket": "/run/query/query.sock"}
	config, _ := json.Marshal(cfg)
	credentials, _ := json.Marshal(objectstore.Config{Endpoint: "http://history-s3:9000", Bucket: "history", Region: "us-east-1", AccessKey: "test-access-key", SecretKey: "test-secret-key"})
	if e := os.WriteFile(filepath.Join(dir, "query.json"), config, 0644); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "r2.json"), credentials, 0644); e != nil {
		t.Fatal(e)
	}
	docker(t, nil, "volume", "create", volume)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
		exec.CommandContext(ctx, "docker", "volume", "rm", volume).Run()
	})
	docker(t, nil, "run", "-d", "--name", name, "--memory", "512m", "--cpus", "1", "--pids-limit", "64", "--ulimit", "nofile=12288:12288", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--tmpfs", "/tmp:size=1g,mode=1777", "--network", network, "-v", dir+":/run/gatebeam:ro", "-v", volume+":/run/query", os.Getenv("GATEBEAM_TEST_QUERY_IMAGE"))
	// Inspect actual production-mode capability mounts, not just Compose text.
	actual := string(docker(t, nil, "inspect", "--format", "{{json .HostConfig}} {{json .Mounts}}", name))
	for _, forbidden := range []string{"database-url", "ca-signer", "identity-file", "edge-runtime"} {
		if strings.Contains(actual, forbidden) {
			t.Fatal("forbidden process mount", forbidden)
		}
	}
	payload, _ := json.Marshal(struct {
		Filter  domain.QueryFilter
		Objects []domain.Object
	}{domain.QueryFilter{SiteIDs: []string{m.Objects[0].SiteID}, From: m.Objects[0].MinTime.Add(-time.Second), To: m.Objects[0].MaxTime.Add(time.Second)}, m.Objects})
	// Docker can emit host capability warnings on stderr even when curl succeeds.
	// Keep the JSON protocol on stdout separate; docker logs above/below still
	// use CombinedOutput so credential-leak checks inspect both log streams.
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	query := exec.CommandContext(ctx, "docker", "run", "--rm", "-i", "--user", "101:101", "--memory", "64m", "--cpus", "0.5", "--pids-limit", "64", "--network", "none", "--read-only", "-v", volume+":/run/query:ro", "curlimages/curl@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93", "--silent", "--show-error", "--fail", "--retry", "5", "--retry-connrefused", "--retry-delay", "1", "--max-time", "8", "--unix-socket", "/run/query/query.sock", "-H", "Content-Type: application/json", "--data-binary", "@-", "http://query/execute")
	query.Stdin = bytes.NewReader(payload)
	response, queryErr := query.Output()
	if queryErr != nil {
		t.Fatal("owned query client failed", queryErr)
	}
	var rows []domain.QueryRow
	if e := json.Unmarshal(response, &rows); e != nil || len(rows) != 1 {
		t.Fatal("production worker query failed", string(response), e)
	}
	if logs := string(docker(t, nil, "logs", name)); strings.Contains(logs, "test-secret-key") || strings.Contains(logs, "test-access-key") {
		t.Fatal("credentials leaked")
	}
}
