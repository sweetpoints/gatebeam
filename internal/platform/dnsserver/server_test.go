package dnsserver

import (
	"net/netip"
	"testing"
)

func TestGCPMetadataAddressIsOnlyADNSDestination(t *testing.T) {
	for raw, want := range map[string]bool{"169.254.169.254:53": true, "169.254.169.254:80": false, "[fd20:ce::254]:53": true, "[fd20:ce::254]:80": false, "169.254.1.1:53": false, "10.42.0.10:5353": true, "127.0.0.1:5353": true} {
		if got := Valid(netip.MustParseAddrPort(raw)); got != want {
			t.Fatalf("%s: %v", raw, got)
		}
	}
}
