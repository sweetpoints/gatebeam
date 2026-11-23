package telegram

import (
	"context"
	"crypto/tls"
	"gatebeam/internal/modules/notification/domain"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSFixedProviderSafeErrorsAndNoRedirect(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/bot123:SECRET/sendMessage" {
			t.Error("unexpected path")
		}
		if calls == 1 {
			http.Error(w, "SECRET provider response", 500)
			return
		}
		if calls == 2 {
			w.Header().Set("Location", "https://attacker.invalid/")
			w.WriteHeader(302)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "example.com"
	transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(server.URL, "https://"))
	}
	sender := Sender{Client: &http.Client{Transport: transport}}
	c := domain.Channel{Recipient: "123"}
	for range 2 {
		err := sender.Send(t.Context(), c, []byte("123:SECRET"), "fixed safe message")
		if err != domain.ErrDelivery {
			t.Fatalf("provider data leaked or redirect accepted: %v", err)
		}
	}
	if err := sender.Send(t.Context(), c, []byte("123:SECRET"), "fixed safe message"); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatal(calls)
	}
}
