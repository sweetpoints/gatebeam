package domain_test

import (
	"gatebeam/internal/modules/certificates/domain"
	"testing"
)

func TestInternalClientIdentityPolicy(t *testing.T) {
	spec := domain.Spec{Names: []string{"gateway.internal.test"}, Purpose: "clientAuth", Method: "acme", ProviderID: "account", Challenge: "http-01", TrustID: "root", TrustRevision: 1}
	if err := spec.Validate(); err != nil {
		t.Fatalf("standard client ACME spec rejected: %v", err)
	}
	for _, provider := range []string{"internal-client", "internal-server"} {
		if err := (domain.ProviderAccount{Provider: provider, Email: "ops@example.test", EABKeyID: "one-time"}).Validate(); err != nil {
			t.Fatalf("dedicated directory account rejected: %v", err)
		}
	}
}

func TestDirectoryCannotChangeClientPurpose(t *testing.T) {
	client := domain.Spec{Names: []string{"gateway.internal.test"}, Purpose: "clientAuth", Method: "acme", ProviderID: "account", Challenge: "http-01", TrustID: "root", TrustRevision: 1}
	for _, provider := range []string{"letsencrypt", "zerossl", "google", "internal-server", "internal-client"} {
		account := domain.ProviderAccount{Provider: provider, Email: "ops@example.test", EABKeyID: "eab"}
		if got := account.Accepts(client); got != (provider == "internal-client") {
			t.Fatalf("%s accepted client=%v", provider, got)
		}
	}
	account := domain.ProviderAccount{Provider: "internal-client", Email: "ops@example.test", EABKeyID: "eab"}
	client.Purpose = "serverAuth"
	if account.Accepts(client) {
		t.Fatal("client directory accepted server purpose")
	}
	client.Purpose = "clientAuth"
	client.TrustID = ""
	client.TrustRevision = 0
	if account.Accepts(client) {
		t.Fatal("internal identity without explicit trust accepted")
	}
	account.EABKeyID = ""
	if account.Validate() == nil {
		t.Fatal("internal account without EAB accepted")
	}
}
