package status_test

import (
	"gatebeam/internal/modules/certificates/infrastructure/status"
	"testing"
)

func TestUntrustedStatusProfileRejected(t *testing.T) {
	valid := func() status.Profile {
		return status.Profile{ID: "p", Fingerprints: []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, ResolverServers: []string{"10.0.0.53:53"}, AllowedNetworks: []string{"10.0.0.0/24"}, CRLURLs: map[string]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "http://status.owned.test/crl"}, OCSPURLs: map[string]string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": "http://status.owned.test/ocsp"}}
	}
	if _, err := status.New([]status.Profile{valid()}); err != nil {
		t.Fatal("positive profile rejected", err)
	}
	for _, tc := range []struct {
		name   string
		change func(*status.Profile)
	}{
		{"missing-id", func(p *status.Profile) { p.ID = "" }},
		{"missing-fingerprints", func(p *status.Profile) { p.Fingerprints = nil }},
		{"unspecified-resolver", func(p *status.Profile) { p.ResolverServers = []string{"0.0.0.0:53"} }},
		{"unrestricted-network", func(p *status.Profile) { p.AllowedNetworks = []string{"0.0.0.0/0"} }},
		{"unsupported-crl-scheme", func(p *status.Profile) {
			p.CRLURLs["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"] = "file:///private/crl"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := valid()
			tc.change(&p)
			if _, err := status.New([]status.Profile{p}); err == nil {
				t.Fatal("untrusted profile accepted")
			}
		})
	}
}
