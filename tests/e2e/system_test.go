package e2e_test

import (
	"go.yaml.in/yaml/v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type service struct {
	Image    string         `yaml:"image"`
	Build    any            `yaml:"build"`
	Profiles []string       `yaml:"profiles"`
	User     string         `yaml:"user"`
	ReadOnly bool           `yaml:"read_only"`
	Volumes  []string       `yaml:"volumes"`
	Networks map[string]any `yaml:"networks"`
	Memory   string         `yaml:"mem_limit"`
	Tmpfs    []string       `yaml:"tmpfs"`
	PIDs     int            `yaml:"pids_limit"`
}

func TestCompositionUsesPrebuiltImages(t *testing.T) {
	for name, s := range composition(t) {
		if s.Build != nil {
			t.Errorf("%s must not build an image during deployment", name)
		}
		if strings.TrimSpace(s.Image) == "" {
			t.Errorf("%s must reference a prebuilt image", name)
		}
	}
}

func composition(t *testing.T) map[string]service {
	return compositionFile(t, "compose.yaml")
}

func compositionFile(t *testing.T, name string) map[string]service {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Services map[string]service `yaml:"services"`
	}
	if err = yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	return config.Services
}

func TestProductionCompositionHasOnlyDefaultRuntimeServices(t *testing.T) {
	services := composition(t)
	required := map[string]bool{"nginx": true, "management": true, "background-jobs": true, "log-query": true}
	for name, s := range services {
		if !required[name] {
			t.Errorf("non-runtime service %s belongs outside production Compose", name)
		}
		if len(s.Profiles) != 0 {
			t.Errorf("production service %s must start without selecting a profile", name)
		}
	}
	for name := range required {
		if _, ok := services[name]; !ok {
			t.Errorf("missing production service %s", name)
		}
	}
	if _, ok := services["postgres"]; ok {
		t.Error("production database belongs outside gateway Compose")
	}
}

func TestDevelopmentDatabaseIsSeparate(t *testing.T) {
	services := compositionFile(t, "compose.dev.yaml")
	s, ok := services["postgres"]
	if !ok || len(services) != 1 {
		t.Fatal("development Compose must contain only its local database")
	}
	if !strings.Contains(s.Image, "@sha256:") || len(s.Profiles) != 0 || s.Build != nil {
		t.Fatal("development database must use a pinned prebuilt image without profiles")
	}
}
func TestCompositionProcessCapabilities(t *testing.T) {
	services := composition(t)
	for _, name := range []string{"management", "background-jobs", "nginx", "log-query"} {
		s, ok := services[name]
		if !ok {
			t.Errorf("missing actual %s process", name)
			continue
		}
		if s.User != "101:101" || !s.ReadOnly || s.Memory == "" || s.PIDs < 1 {
			t.Errorf("%s lacks bounded unprivileged runtime", name)
		}
		for _, mount := range s.Tmpfs {
			if !strings.HasPrefix(mount, "/") {
				t.Errorf("%s malformed tmpfs mount: %s", name, mount)
			}
		}
		for _, mount := range s.Volumes {
			if strings.Contains(mount, "docker.sock") || strings.Contains(mount, "offline-root") {
				t.Errorf("forbidden runtime mount: %s", name)
			}
			if name == "management" && (strings.Contains(mount, "query-socket") || strings.Contains(mount, "secrets/ca") || strings.Contains(mount, "secrets/worker")) {
				t.Errorf("API gained forbidden capability: %s", mount)
			}
		}
	}
	edge, worker := strings.Join(services["nginx"].Volumes, "\n"), strings.Join(services["background-jobs"].Volumes, "\n")
	if !strings.Contains(edge, "acme-challenges:/var/lib/gatebeam/acme") || !strings.Contains(worker, "acme-challenges:/var/lib/gatebeam/acme") {
		t.Error("coordinated issuance requires a node-local edge-write HTTP01 webroot")
	}
	if _, ok := services["log-query"].Networks["node-private"]; ok {
		t.Error("query executor can reach control database network")
	}
	for _, name := range []string{"nginx", "management", "background-jobs", "log-query"} {
		if !strings.Contains(services[name].Image, ":?") {
			t.Errorf("%s image is mutable", name)
		}
	}
}

func TestFullAcceptanceRequiresExplicitDualNodeGate(t *testing.T) {
	script, e := os.ReadFile(filepath.Join("..", "..", "scripts", "check-system.py"))
	if e != nil {
		t.Fatal(e)
	}
	for _, required := range []string{"dual-node-runtime-control-upgrade-capacity", "scripts/check-multinode.sh", ".work/artifacts/manifest.json", "tests/fixtures/multinode/config.json", "tests/fixtures/multinode/budget.json", "GATEBEAM_COMPOSE_EXACT_IMAGES"} {
		if !strings.Contains(string(script), required) {
			t.Fatalf("full acceptance missing %s", required)
		}
	}
}
