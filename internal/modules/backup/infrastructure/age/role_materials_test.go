package age

import (
	"slices"
	"testing"
)

func TestRoleCapsuleIncludesOnlyOwnedManagementTLS(t *testing.T) {
	for role, files := range map[string][]string{"api": {"api-tls.pem", "api-tls.key", "api-trust.pem"}, "edge": {"api-client.pem", "api-client.key", "api-trust.pem", "management-upstreams.json"}} {
		for _, f := range files {
			if !slices.Contains(AllowedFiles(role), f) {
				t.Fatal("new TLS/state material missing from owning capsule", role, f)
			}
		}
	}
	for _, role := range []string{"worker", "ca"} {
		for _, f := range []string{"api-tls.key", "api-client.key", "management-upstreams.json"} {
			if slices.Contains(AllowedFiles(role), f) {
				t.Fatal("foreign role could export private management identity", role, f)
			}
		}
	}
}
