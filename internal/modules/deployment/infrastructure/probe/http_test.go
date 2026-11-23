package probe

import (
	"context"
	health "gatebeam/internal/modules/deployment/application/health"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestProbePinsAddressAndHostWithoutRedirect(t *testing.T) {
	var host string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		http.Redirect(w, r, "http://169.254.169.254/", 302)
	}))
	defer srv.Close()
	addr := netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://"))
	e := (HTTP{}).Check(context.Background(), health.Probe{Address: addr, Protocol: "http", HTTPHost: "business.example", Path: "/health"})
	if e == nil || host != "business.example" {
		t.Fatal(host, e)
	}
}
func TestProbeVerifiesTLSName(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	e := (HTTP{}).Check(ctx, health.Probe{Address: netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "https://")), Protocol: "https", HTTPHost: "business.example", TLSName: "wrong.example", Path: "/"})
	if e == nil {
		t.Fatal("untrusted TLS accepted")
	}
}

func TestProbeUsesCallerTimeoutBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(2200 * time.Millisecond):
			w.WriteHeader(200)
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if e := (HTTP{}).Check(ctx, health.Probe{Address: netip.MustParseAddrPort(strings.TrimPrefix(srv.URL, "http://")), Protocol: "http", HTTPHost: "business.example", Path: "/health"}); e != nil {
		t.Fatal("hardcoded shorter timeout overrode explicit caller budget", e)
	}
}
