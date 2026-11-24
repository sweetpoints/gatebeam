package http01

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

type resolver struct{ ips []net.IPAddr }

func (r resolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) { return r.ips, nil }
func TestValidationPinsAllAnswersAndRejectsRedirectEscape(t *testing.T) {
	served := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		if r.Host != "a.example" {
			t.Error("wrong host")
		}
		if r.URL.Query().Get("escape") == "yes" {
			http.Redirect(w, r, "http://metadata.example/", 302)
			return
		}
		w.Write([]byte("token.thumb\n"))
	}))
	defer server.Close()
	v, e := New([]string{"10.32.0.0/24"}, []string{"10.32.0.1/32"})
	if e != nil {
		t.Fatal(e)
	}
	v.resolver = resolver{[]net.IPAddr{{IP: net.ParseIP("10.32.0.2")}}}
	v.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.32.0.2:80" {
			t.Fatalf("unvalidated dial %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}
	if e = v.Validate(context.Background(), "a.example", "token", "token.thumb"); e != nil {
		t.Fatal(e)
	}
	v.resolver = resolver{[]net.IPAddr{{IP: net.ParseIP("10.32.0.2")}, {IP: net.ParseIP("169.254.169.254")}}}
	if e = v.Validate(context.Background(), "a.example", "token", "token.thumb"); e == nil || served != 1 {
		t.Fatal("mixed DNS answer reached network")
	}
	for _, ip := range []string{"127.0.0.1", "10.32.0.1", "10.31.0.2", "169.254.169.254", "100.100.100.200", "8.8.8.8", "::ffff:10.32.0.2"} {
		if v.allowed(netip.MustParseAddr(ip)) {
			t.Fatal("unsafe IP", ip)
		}
	}
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		served++
		http.Redirect(w, r, "http://metadata.example/", 302)
	})
	v.resolver = resolver{[]net.IPAddr{{IP: net.ParseIP("10.32.0.2")}}}
	if e = v.Validate(context.Background(), "a.example", "token", "token.thumb"); e == nil || served != 2 {
		t.Fatal("cross-host redirect followed")
	}
}
func TestIPv6MetadataDeniedEvenInsideAuthorizedULA(t *testing.T) {
	v, e := New([]string{"fc00::/7"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"fd00:ec2::254", "fd20:ce::254"} {
		if v.allowed(netip.MustParseAddr(ip)) {
			t.Fatal("metadata address allowed", ip)
		}
	}
	if !v.allowed(netip.MustParseAddr("fd40:1234::2")) {
		t.Fatal("ordinary authorized ULA blocked")
	}
}
