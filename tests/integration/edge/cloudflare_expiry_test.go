package edge_test

import (
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"net/http"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestNativeCloudflareExpiresWithoutControlPlane(t *testing.T) {
	f := setup(t)
	cf := f.addSite(t, "expiry.test")
	cf.Cloudflare = app.CFPolicy{Mode: "proxied"}
	f.addSite(t, "unaffected.test")
	// This is cache input validity, not a request/expiry-enforcement deadline.
	// The software CPU must finish its bounded20s startup before probing it.
	validityWindow := 5 * time.Second
	if os.Getenv("GATEBEAM_ACCEPTANCE_EXECUTION") == "software-emulated-vm" {
		validityWindow = 30 * time.Second
	}
	var expiry time.Time
	gateway := command(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", f.name)
	f.state.Cloudflare = edge.CloudflareSet{Generation: "expiry-source", ValidUntil: time.Now().Add(time.Hour), Networks: []netip.Prefix{netip.MustParsePrefix(gateway + "/32")}}
	f.startBeforeLaunch(t, func() {
		expiry = time.Now().Add(validityWindow).Truncate(time.Second)
		f.state.Cloudflare.ValidUntil = expiry
	})
	client := f.client("expiry.test", nil)
	// Reuse the prepared TLS connection near the boundary so its handshake
	// cannot consume the remaining validity window before the HTTP request.
	client.Transport.(*http.Transport).DisableKeepAlives = false
	t.Cleanup(client.CloseIdleConnections)
	t.Logf("CF fixture input validity=%s; remaining after startup=%s", validityWindow, time.Until(expiry))
	headers := map[string]string{"CF-Connecting-IP": "203.0.113.8"}
	before, _ := request(t, client, "expiry.test", "/", "", headers)
	if before != 200 {
		t.Fatal("valid CF cache denied", before)
	}
	// No worker, DB, configuration rewrite, or reload participates after start.
	time.Sleep(time.Until(expiry.Add(-time.Second)))
	nearExpiry, _ := request(t, client, "expiry.test", "/", "", headers)
	if nearExpiry != 200 {
		t.Fatal("still-valid CF cache denied near expiry", nearExpiry)
	}
	time.Sleep(time.Until(expiry.Add(200 * time.Millisecond)))
	after, _ := request(t, client, "expiry.test", "/", "", headers)
	if after != 403 {
		t.Fatal("expired authoritative source retained native trust", after)
	}
	unaffected, _ := request(t, f.client("unaffected.test", nil), "unaffected.test", "/", "", nil)
	if unaffected != 200 {
		t.Fatal("expiry interrupted unrelated route", unaffected)
	}
}
