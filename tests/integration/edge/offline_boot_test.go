//go:build integration

package edge_test

import (
	"context"
	"encoding/json"
	"gatebeam/internal/platform/bootstrap"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestEdgeStartsWithoutControlServices(t *testing.T) {
	binary := os.Getenv("GATEBEAM_I4_BINARY")
	if binary == "" {
		t.Fatal("run scripts/check-edge.sh supervisor")
	}
	nativeTests := filepath.Join(filepath.Dir(filepath.Dir(binary)), "supervisor.test")
	for _, database := range []string{"unreadable-secret", "refused-connection", "backup-unavailable"} {
		t.Run(database, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0755); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			if err := os.Mkdir(state, 0777); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(state, 0777); err != nil {
				t.Fatal(err)
			} // isolated test mount parent only; /state/runtime is UID101/0700
			cfg := bootstrap.Config{Environment: "production", Mode: "edge", RuntimeProtocol: 1, NodeID: "11111111-1111-4111-8111-111111111111", NodeEpoch: 1, EdgeRoot: "/state/runtime", DatabaseFile: "/fixture/missing-secret", ManagementDomain: "management.test", ManagementAPIAddress: "10.254.254.2:8080", ManagementCertificateFile: "/fixture/unavailable.pem", ManagementKeyFile: "/fixture/unavailable.key", ManagementTrustFile: "/fixture/unavailable-ca.pem"}
			if database == "backup-unavailable" {
				cfg.BackupRecipient = "unavailable-recipient"
				cfg.BackupCapsuleDirectory = "/unavailable-capsule"
			}
			if database == "refused-connection" {
				cfg.DatabaseFile = "/fixture/db"
				if err := os.WriteFile(filepath.Join(root, "db"), []byte("postgres://edge:fixture@127.0.0.1:1/gatebeam?sslmode=disable"), 0444); err != nil {
					t.Fatal(err)
				}
			}
			data, _ := json.Marshal(cfg)
			if err := os.WriteFile(filepath.Join(root, "edge.json"), data, 0444); err != nil {
				t.Fatal(err)
			}
			command(t, "docker", "run", "--rm", "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--network", "none", "--tmpfs", "/tmp:size=32m,mode=1777", "--mount", "type=bind,src="+state+",dst=/state", "--mount", "type=bind,src="+nativeTests+",dst=/supervisor.test,readonly", "-e", "GATEBEAM_TEST_SEED_BOOT_ROOT=/state/runtime", "--entrypoint", "/supervisor.test", image, "-test.run", "^TestNativeSeedOfflineFixture$", "-test.timeout=20s")
			name := "gatebeam-offline-" + database + "-" + time.Now().Format("150405.000000000")
			command(t, "docker", "create", "--name", name, "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--pids-limit", "64", "--tmpfs", "/tmp:size=32m,mode=1777", "--mount", "type=bind,src="+state+",dst=/state", "--mount", "type=bind,src="+root+",dst=/fixture,readonly", "--mount", "type=bind,src="+binary+",dst=/gatebeam,readonly", "-p", "127.0.0.1::8080", "--entrypoint", "/gatebeam", image, "--config", "/fixture/edge.json")
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
			})
			command(t, "docker", "start", name)
			client := &http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}
			await := func() {
				port := strings.TrimPrefix(command(t, "docker", "port", name, "8080/tcp"), "127.0.0.1:")
				deadline := time.Now().Add(8 * time.Second)
				for {
					req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+port+"/", nil)
					req.Host = "route.test"
					resp, err := client.Do(req)
					if err == nil {
						body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
						resp.Body.Close()
						if resp.StatusCode == 503 && string(body) == "offline-still-serving" {
							return
						}
					}
					if time.Now().After(deadline) {
						t.Fatalf("offline boot did not serve: %v; logs=%s", err, command(t, "docker", "logs", name))
					}
					time.Sleep(50 * time.Millisecond)
				}
			}
			await()
			command(t, "docker", "kill", "--signal", "KILL", name)
			command(t, "docker", "start", name)
			await()
			command(t, "docker", "restart", "--time", "3", name)
			await()
		})
	}
}
