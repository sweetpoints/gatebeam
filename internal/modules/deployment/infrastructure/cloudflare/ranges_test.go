package cloudflare_test

import (
	"context"
	"gatebeam/internal/modules/deployment/infrastructure/cloudflare"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthoritativeRangesAndExpiredCacheFailClosed(t *testing.T) {
	body := `{"success":true,"result":{"ipv4_cidrs":["192.0.2.0/24"],"ipv6_cidrs":["2001:db8::/32"]}}`
	status := 200
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status); _, _ = w.Write([]byte(body)) }))
	defer server.Close()
	source, e := cloudflare.New(server.URL, server.Client(), time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now()
	first, e := source.Fetch(context.Background(), now)
	if e != nil || len(first.Networks) != 2 || !first.ValidUntil.Equal(now.Add(time.Hour)) {
		t.Fatal(first, e)
	}
	status = 503
	cached, e := source.Refresh(context.Background(), first, now.Add(time.Minute))
	if e != nil || len(cached.Networks) != 2 {
		t.Fatal("valid cache was discarded", e)
	}
	closed, e := source.Refresh(context.Background(), first, now.Add(2*time.Hour))
	if e != nil || len(closed.Networks) != 0 || closed.Generation == first.Generation {
		t.Fatal("expired source retained trust", e)
	}
	status = 200
	body = `{"success":true,"result":{"ipv4_cidrs":[],"ipv6_cidrs":[]}}`
	removed, e := source.Refresh(context.Background(), first, now.Add(time.Minute))
	if e != nil || len(removed.Networks) != 0 {
		t.Fatal("known authoritative removal ignored", e)
	}
	body = `{"success":true,"result":{"ipv4_cidrs":["0.0.0.0/0"],"ipv6_cidrs":[]}}`
	if _, e = source.Fetch(context.Background(), now); e == nil {
		t.Fatal("universal trust accepted")
	}
}
