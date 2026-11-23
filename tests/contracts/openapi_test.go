package contracts

import (
	"go.yaml.in/yaml/v3"
	"os"
	"reflect"
	"strings"
	"testing"
)

type specification struct {
	Security []map[string][]string           `yaml:"security"`
	Paths    map[string]map[string]yaml.Node `yaml:"paths"`
}

func readSpec(t *testing.T) specification {
	t.Helper()
	data, e := os.ReadFile("../../api/openapi.yaml")
	if e != nil {
		t.Fatal(e)
	}
	var s specification
	if e = yaml.Unmarshal(data, &s); e != nil {
		t.Fatal(e)
	}
	return s
}
func TestSessionIsDefaultAndBearerOnlyWhereSupported(t *testing.T) {
	spec := readSpec(t)
	session := []map[string][]string{{"session": {}}}
	both := []map[string][]string{{"session": {}}, {"bearer": {}}}
	if !reflect.DeepEqual(spec.Security, session) {
		t.Fatalf("default security = %#v; want session only", spec.Security)
	}
	public := map[string]bool{"/auth/login": true, "/auth/login/finish": true, "/auth/enroll": true, "/auth/recover": true}
	count := 0
	for path, item := range spec.Paths {
		for method, node := range item {
			switch method {
			case "get", "post", "put", "patch", "delete":
			default:
				continue
			}
			count++
			var op struct {
				Security *[]map[string][]string `yaml:"security"`
			}
			if e := node.Decode(&op); e != nil {
				t.Fatal(e)
			}
			effective := spec.Security
			if op.Security != nil {
				effective = *op.Security
			}
			switch {
			case (strings.HasPrefix(path, "/certificates/") && method == "get") || path == "/statistics/query" || strings.HasPrefix(path, "/log-queries") || path == "/auth/session" || path == "/ingress-capabilities" || strings.HasPrefix(path, "/sites") || strings.HasPrefix(path, "/targets") || strings.HasPrefix(path, "/groups") || strings.HasPrefix(path, "/releases"):
				if !reflect.DeepEqual(effective, both) {
					t.Errorf("%s %s must support session or bearer", method, path)
				}
			case public[path]:
				if op.Security == nil || len(effective) != 0 {
					t.Errorf("%s %s must explicitly allow unauthenticated requests", method, path)
				}
			default:
				if !reflect.DeepEqual(effective, session) {
					t.Errorf("%s %s must be session only", method, path)
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("no operations checked")
	}
}
func TestLogoutDocumentsBodylessCSRFRequest(t *testing.T) {
	spec := readSpec(t)
	node, ok := spec.Paths["/auth/logout"]["post"]
	if !ok {
		t.Fatal("logout operation missing")
	}
	var op struct {
		RequestBody *yaml.Node `yaml:"requestBody"`
		Parameters  []struct {
			Ref string `yaml:"$ref"`
		} `yaml:"parameters"`
	}
	if e := node.Decode(&op); e != nil {
		t.Fatal(e)
	}
	if op.RequestBody != nil {
		t.Fatal("logout must not require a body")
	}
	for _, p := range op.Parameters {
		if p.Ref == "#/components/parameters/CSRF" {
			return
		}
	}
	t.Fatal("logout CSRF header contract missing")
}

func TestIngressMutationRevisionAndIdempotencyContracts(t *testing.T) {
	spec := readSpec(t)
	mutations := 0
	for path, ops := range spec.Paths {
		if !strings.HasPrefix(path, "/sites") && !strings.HasPrefix(path, "/groups") && !strings.HasPrefix(path, "/targets") {
			continue
		}
		for method, node := range ops {
			// This POST is a scoped read-only network query, not an ingress mutation.
			if path == "/sites/{id}/preflight" && method == "post" {
				continue
			}
			if method != "post" && method != "put" && method != "delete" {
				continue
			}
			mutations++
			var op struct {
				Parameters []struct {
					Ref string `yaml:"$ref"`
				}
				RequestBody struct {
					Content map[string]struct {
						Schema struct {
							AdditionalProperties bool `yaml:"additionalProperties"`
							Required             []string
							Properties           map[string]yaml.Node
						}
					}
				} `yaml:"requestBody"`
			}
			if e := node.Decode(&op); e != nil {
				t.Fatal(e)
			}
			found := false
			for _, p := range op.Parameters {
				if p.Ref == "#/components/parameters/IngressIdempotency" {
					found = true
				}
			}
			if !found {
				t.Errorf("%s %s lacks idempotency", method, path)
			}
			schema := op.RequestBody.Content["application/json"].Schema
			if schema.AdditionalProperties {
				t.Errorf("%s %s accepts arbitrary fields", method, path)
			}
			if _, ok := schema.Properties["actor"]; ok {
				t.Error("request may forge actor")
			}
			if method != "post" {
				found = false
				for _, r := range schema.Required {
					if r == "expected_revision" {
						found = true
					}
				}
				if !found {
					t.Errorf("%s %s lacks revision guard", method, path)
				}
			}
		}
	}
	if mutations != 10 {
		t.Fatalf("mutation contracts %d; want 10", mutations)
	}
}

func TestMigrationPreflightDocumentsReadOnlyPOST(t *testing.T) {
	node := readSpec(t).Paths["/sites/{id}/preflight"]["post"]
	var op struct {
		ReadOnly   bool `yaml:"x-read-only"`
		Parameters []struct {
			Ref string `yaml:"$ref"`
		}
		Responses map[string]yaml.Node
	}
	if e := node.Decode(&op); e != nil {
		t.Fatal(e)
	}
	if !op.ReadOnly || op.Responses["200"].Kind == 0 || op.Responses["201"].Kind != 0 || op.Responses["202"].Kind != 0 {
		t.Fatal("preflight must remain a read-only synchronous query")
	}
	csrf := false
	for _, p := range op.Parameters {
		if p.Ref == "#/components/parameters/IngressIdempotency" {
			t.Fatal("read-only query stores a mutation receipt")
		}
		if p.Ref == "#/components/parameters/CSRF" {
			csrf = true
		}
	}
	if !csrf {
		t.Fatal("session POST requires CSRF")
	}
}
