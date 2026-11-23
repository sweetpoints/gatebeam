package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestForbiddenImports(t *testing.T) {
	cases := []struct{ path, dependency string }{
		{"internal/modules/a/domain/a.go", "github.com/labstack/echo/v5"},
		{"internal/modules/a/application/a.go", "github.com/jackc/pgx/v5"},
		{"internal/modules/a/domain/a.go", "net/http"},
		{"internal/modules/a/domain/a.go", "os"},
		{"internal/modules/a/application/a.go", "example.com/vendor/sdk"},
		{"internal/modules/a/application/a.go", "gatebeam/internal/modules/b/domain"},
		{"internal/modules/a/application/a.go", "gatebeam/internal/modules/b/application"},
		{"internal/modules/a/domain/a.go", "gatebeam/internal/modules/a/application"},
		{"internal/platform/a.go", "gatebeam/internal/modules/a/domain"},
		{"internal/modules/a/transport/http/a.go", "gatebeam/internal/modules/a/infrastructure/postgres"},
	}
	for _, tc := range cases {
		t.Run(tc.path+tc.dependency, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, tc.path)
			os.MkdirAll(filepath.Dir(p), 0755)
			os.WriteFile(p, []byte("package a\nimport _ \""+tc.dependency+"\"\n"), 0600)
			if err := check(root); err == nil {
				t.Fatal("accepted forbidden import")
			}
		})
	}
}
func TestAllowedImports(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "internal/modules/a/application/a.go")
	os.MkdirAll(filepath.Dir(p), 0755)
	os.WriteFile(p, []byte("package a\nimport (\"context\";\"gatebeam/internal/modules/a/domain\")"), 0600)
	if err := check(root); err != nil {
		t.Fatal(err)
	}
}

func TestImportCycleRejected(t *testing.T) {
	root := t.TempDir()
	for name, dep := range map[string]string{"a": "b", "b": "a"} {
		p := filepath.Join(root, "internal/platform", name, "file.go")
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("package "+name+"\nimport _ \"gatebeam/internal/platform/"+dep+"\"\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := check(root); err == nil {
		t.Fatal("accepted import cycle")
	}
}

func TestExternalIntegrationTestsAreNotProductionDependencies(t *testing.T) {
	for _, tc := range []struct {
		name, pkg string
		wantError bool
	}{{"integration_test.go", "auth_test", false}, {"production.go", "auth", true}, {"internal_test.go", "auth", true}} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			p := filepath.Join(root, "internal/modules/a/application/auth", tc.name)
			if e := os.MkdirAll(filepath.Dir(p), 0755); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(p, []byte("//go:build integration\n\npackage "+tc.pkg+"\nimport (_ \"gatebeam/internal/modules/a/application/auth\";_ \"gatebeam/internal/modules/a/infrastructure/postgres\";_ \"github.com/jackc/pgx/v5\")\n"), 0600); e != nil {
				t.Fatal(e)
			}
			e := check(root)
			if (e != nil) != tc.wantError {
				t.Fatalf("check error %v; wantError %v", e, tc.wantError)
			}
		})
	}
}

func TestOnlyPureNetIPParsingAllowedInInnerLayers(t *testing.T) {
	for _, layer := range []string{"domain", "application"} {
		src := "internal/modules/ingress/" + layer + "/address.go"
		if forbidden(src, "net/netip") {
			t.Fatalf("pure value parsing must be allowed in %s", layer)
		}
		for _, dep := range []string{"net", "net/http", "net/url", "net/rpc", "net/textproto"} {
			if !forbidden(src, dep) {
				t.Fatalf("network import %s permitted in %s", dep, layer)
			}
		}
	}
}
