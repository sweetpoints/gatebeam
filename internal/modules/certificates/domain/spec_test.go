package domain_test

import (
	"gatebeam/internal/modules/certificates/domain"
	"testing"
	"time"
)

func TestRenewalCompatibilityAndImportPolicy(t *testing.T) {
	s := domain.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: "account", Challenge: "dns-01", CredentialIDs: []string{"dns"}}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	n := s
	n.Names = []string{"changed.test"}
	if s.Compatible(n) {
		t.Fatal("name change classified as renewal")
	}
	n = s
	n.Purpose = "clientAuth"
	if s.Compatible(n) {
		t.Fatal("purpose change classified as renewal")
	}
	n = s
	n.TrustID = "new-trust"
	if s.Compatible(n) {
		t.Fatal("trust change classified as renewal")
	}
	if !s.Compatible(s) {
		t.Fatal("unchanged specification incompatible")
	}
	s.Method = "import"
	s.ProviderID = ""
	s.Challenge = ""
	s.CredentialIDs = nil
	if s.Validate() != nil || s.Automatic() {
		t.Fatal("import claimed automatic renewal")
	}
}
func TestVersionValidityAndFailureBackoff(t *testing.T) {
	now := time.Now()
	v := domain.Version{NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if !v.Usable(now) || v.Usable(v.NotAfter) {
		t.Fatal("validity boundary")
	}
	state := domain.Attempt{}
	state = state.Failed(now)
	if !state.NextAttempt.After(now) || state.Failures != 1 {
		t.Fatal("missing persistent backoff")
	}
	for i := 0; i < 30; i++ {
		state = state.Failed(now)
	}
	if state.NextAttempt.After(now.Add(24 * time.Hour)) {
		t.Fatal("unbounded retry delay")
	}
}
