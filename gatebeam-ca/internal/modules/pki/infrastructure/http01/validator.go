// Package http01 validates standard HTTP-01 on port 80 inside explicitly
// authorized private networks. Proxy variables and implicit DNS dialing are unused.
package http01

import (
	"context"
	"errors"
	"gatebeam-ca/internal/modules/pki/domain"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

var ErrValidation = errors.New("HTTP-01 validation failed")

type lookup interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type Validator struct {
	networks, denied []netip.Prefix
	resolver         lookup
	dial             func(context.Context, string, string) (net.Conn, error)
}

func New(networks, denied []string) (*Validator, error) {
	v := &Validator{resolver: net.DefaultResolver, dial: (&net.Dialer{Timeout: 3 * time.Second}).DialContext}
	if len(networks) == 0 || len(networks) > 64 || len(denied) > 128 {
		return nil, ErrValidation
	}
	for _, raw := range networks {
		p, e := netip.ParsePrefix(raw)
		if e != nil || !p.Addr().IsPrivate() || p.Addr().Is4In6() || p != p.Masked() || (p.Addr().Is4() && p.Bits() < 8) || (!p.Addr().Is4() && p.Bits() < 7) {
			return nil, ErrValidation
		}
		v.networks = append(v.networks, p)
	}
	for _, raw := range denied {
		p, e := netip.ParsePrefix(raw)
		if e != nil {
			return nil, ErrValidation
		}
		v.denied = append(v.denied, p)
	}
	return v, nil
}
func (v *Validator) allowed(ip netip.Addr) bool {
	// Cloud metadata includes ULA endpoints, not only IPv4 link-local.
	// AWS EC2 IMDS and Google Compute metadata IPv6 endpoints.
	if ip == netip.MustParseAddr("fd00:ec2::254") || ip == netip.MustParseAddr("fd20:ce::254") {
		return false
	}
	if !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Is4In6() || ip.Zone() != "" {
		return false
	}
	for _, p := range v.denied {
		if p.Contains(ip) {
			return false
		}
	}
	for _, p := range v.networks {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
func (v *Validator) Validate(ctx context.Context, name, token, expected string) error {
	if _, e := domain.NewPolicy([]string{name}, domain.ServerAuth); e != nil {
		return ErrValidation
	}
	if token == "" || len(token) > 128 || strings.ContainsAny(token, "/?#%\\ ") {
		return ErrValidation
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	target := "http://" + name + "/.well-known/acme-challenge/" + token
	for attempt := 0; attempt < 4; attempt++ {
		u, e := url.Parse(target)
		if e != nil || u.Scheme != "http" || u.Hostname() != name || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "80") {
			return ErrValidation
		}
		ips, e := v.resolver.LookupIPAddr(ctx, name)
		if e != nil || len(ips) == 0 || len(ips) > 32 {
			return ErrValidation
		}
		pinned := make([]netip.Addr, 0, len(ips))
		for _, raw := range ips {
			ip, ok := netip.AddrFromSlice(raw.IP)
			ip = ip.Unmap()
			if !ok || raw.Zone != "" || !v.allowed(ip) {
				return ErrValidation
			}
			pinned = append(pinned, ip)
		}
		tr := &http.Transport{DisableKeepAlives: true, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 8192, DialContext: func(c context.Context, network, address string) (net.Conn, error) {
			if address != net.JoinHostPort(name, "80") {
				return nil, ErrValidation
			}
			// Every connection uses only this hop's checked answers, without re-resolving.
			return v.dial(c, "tcp", net.JoinHostPort(pinned[0].String(), "80"))
		}}
		client := &http.Client{Transport: tr, Timeout: 4 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, "GET", target, nil)
		if e != nil {
			return ErrValidation
		}
		resp, e := client.Do(req)
		if e != nil {
			tr.CloseIdleConnections()
			return ErrValidation
		}
		body, e := io.ReadAll(io.LimitReader(resp.Body, 4097))
		resp.Body.Close()
		tr.CloseIdleConnections()
		if e != nil || len(body) > 4096 {
			return ErrValidation
		}
		if resp.StatusCode == 200 {
			if strings.TrimRight(string(body), " \t\r\n") == expected {
				return nil
			}
			return ErrValidation
		}
		if resp.StatusCode != 301 && resp.StatusCode != 302 && resp.StatusCode != 303 && resp.StatusCode != 307 && resp.StatusCode != 308 {
			return ErrValidation
		}
		next, e := resp.Location()
		if e != nil {
			return ErrValidation
		}
		target = next.String()
	}
	return ErrValidation
}
