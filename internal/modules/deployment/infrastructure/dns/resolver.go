// Package dns constrains every DNS refresh before it can become a runtime generation.
package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

var ErrForbidden = errors.New("target address is outside authorized private networks")

type Lookup interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}
type Resolver struct {
	Lookup             Lookup
	Allowed, Protected []netip.Prefix
	Timeout            time.Duration
}

func Check(ip netip.Addr, allowed, protected []netip.Prefix) error {
	ip = ip.Unmap()
	// Provider metadata addresses inside ULA ranges remain forbidden even when
	// an operator authorizes the containing private network.
	if ip == netip.MustParseAddr("fd00:ec2::254") || ip == netip.MustParseAddr("fd20:ce::254") {
		return ErrForbidden
	}
	if !ip.IsValid() || ip.Zone() != "" || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return ErrForbidden
	}
	for _, p := range protected {
		if p.Contains(ip) {
			return ErrForbidden
		}
	}
	for _, p := range allowed {
		if p.Contains(ip) {
			return nil
		}
	}
	return ErrForbidden
}
func (r Resolver) Resolve(ctx context.Context, name string) ([]netip.Addr, error) {
	if name == "" || strings.ContainsAny(name, "/\\:;{}$\"' \t\r\n") {
		return nil, ErrForbidden
	}
	d := r.Timeout
	if d <= 0 || d > 5*time.Second {
		d = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, d)
	defer cancel()
	l := r.Lookup
	if l == nil {
		l = net.DefaultResolver
	}
	ips, e := l.LookupNetIP(ctx, "ip", name)
	if e != nil {
		return nil, e
	}
	if len(ips) == 0 || len(ips) > 100 {
		return nil, ErrForbidden
	}
	out := []netip.Addr{}
	seen := map[netip.Addr]bool{}
	for _, ip := range ips {
		ip = ip.Unmap()
		if e := Check(ip, r.Allowed, r.Protected); e != nil {
			return nil, e
		}
		if !seen[ip] {
			out = append(out, ip)
			seen[ip] = true
		}
	}
	return out, nil
}
