// Package dnsserver validates operator-pinned DNS destinations, not HTTP peers.
package dnsserver

import "net/netip"

func Valid(server netip.AddrPort) bool {
	ip := server.Addr().Unmap()
	if !server.IsValid() || server.Port() == 0 || server.Addr().Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
		return false
	}
	if ip == netip.MustParseAddr("169.254.169.254") || ip == netip.MustParseAddr("fd20:ce::254") {
		return server.Port() == 53
	}
	return !ip.IsLinkLocalUnicast()
}
