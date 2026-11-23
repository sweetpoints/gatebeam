//go:build integration

package compose_test

import (
	"go.yaml.in/yaml/v3"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProductionComposeHasFiveRolesAndNoDatabase(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "../../..")
	raw, e := os.ReadFile(filepath.Join(root, "compose.yaml"))
	if e != nil {
		t.Fatal(e)
	}
	var cfg map[string]any
	if e = yaml.Unmarshal(raw, &cfg); e != nil {
		t.Fatal(e)
	}
	services := cfg["services"].(map[string]any)
	if len(services) != 5 || services["postgres"] != nil {
		t.Fatal("production must have exactly five roles and an external database")
	}
	for _, name := range []string{"nginx", "management", "background-jobs", "internal-ca", "log-query"} {
		role, ok := services[name].(map[string]any)
		if !ok {
			t.Fatal("missing role", name)
		}
		if role["build"] != nil || role["depends_on"] != nil || role["mem_limit"] == nil || role["pids_limit"] == nil {
			t.Fatal("unbounded role or startup control dependency", name)
		}
		if role["restart"] != "on-failure:5" {
			t.Fatal("daemon restart could bypass host mount prerequisites", name)
		}
		if role["read_only"] != true {
			t.Fatal("writable image root", name)
		}
		if !strings.Contains(role["image"].(string), ":?") {
			t.Fatal("image must be explicit", name)
		}
	}
	if strings.Contains(string(raw), "edge-postgres") {
		t.Fatal("database storage in production")
	}
}
