//go:build integration

package multinode

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func (n *Node) RefreshClients(t testing.TB, trust []byte) {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trust) {
		t.Fatal("fixture trust")
	}
	client := func(host, address string, pair *tls.Certificate) *http.Client {
		config := &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
		if pair != nil {
			config.Certificates = []tls.Certificate{*pair}
		}
		return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: config, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		}}}
	}
	cert, e := os.ReadFile(filepath.Join(n.Secrets["nginx"], "api-client.pem"))
	if e != nil {
		t.Fatal(e)
	}
	key, e := os.ReadFile(filepath.Join(n.Secrets["nginx"], "api-client.key"))
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(cert, key)
	clear(key)
	if e != nil {
		t.Fatal(e)
	}
	n.PublicClient = client("management.dual.test", n.Port(t, 443), nil)
	n.APIClient = client("management-api.dual.test", n.Port(t, 9443), &pair)
	n.CAClient = client("ca.dual.test", n.Port(t, 8444), nil)
}
func (b *Business) RefreshClient(t testing.TB, n *Node) {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.Trust)
	address := n.Port(t, 443)
	b.Clients[n.Info.Node.ID] = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "service.dual.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}}}
}
