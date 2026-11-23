package composition

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"gatebeam/internal/platform/bootstrap"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"time"
)

var ErrManagementUnavailable = errors.New("management TLS publication unavailable")

func validateAPIListen(cfg bootstrap.Config) error {
	address := cfg.APIListen
	if address == "" {
		address = "127.0.0.1:8080"
	}
	addr, e := netip.ParseAddrPort(address)
	if e != nil {
		return errors.New("invalid API listen address")
	}
	if addr.Addr().IsLoopback() {
		return nil
	}
	network, e := netip.ParsePrefix(cfg.APIPrivateNetwork)
	if e != nil || !network.Addr().IsPrivate() || !addr.Addr().IsPrivate() || !network.Contains(addr.Addr()) || (addr.Port() != 8080 && cfg.APITLSCertificateFile == "") {
		return errors.New("API must bind loopback or declared private management network")
	}
	return nil
}
func verifyManagement(ctx context.Context, cfg bootstrap.Config) error {
	origin, e := url.Parse(cfg.APIOrigin)
	if e != nil || origin.Scheme != "https" || origin.Hostname() == "" || origin.Hostname() != cfg.ManagementDomain {
		return errors.New("management HTTPS origin required")
	}
	address, e := netip.ParseAddrPort(cfg.ManagementAddress)
	if e != nil || (!address.Addr().IsPrivate() && !address.Addr().IsLoopback()) {
		return errors.New("private management readiness address required")
	}
	trust, e := os.ReadFile(cfg.ManagementTrustFile)
	if e != nil || len(trust) > 1<<20 {
		return errors.New("management trust unavailable")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(trust) {
		return errors.New("invalid management trust")
	}
	expected, e := os.ReadFile(cfg.ManagementCertificateFile)
	if e != nil || len(expected) > 1<<20 {
		return errors.New("management certificate unavailable")
	}
	block, _ := pem.Decode(expected)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("invalid management certificate")
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: cfg.ManagementDomain}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("management readiness redirect denied") }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address.String()+"/_gatebeam/ready", nil)
	if e != nil {
		return e
	}
	req.Host = origin.Host
	resp, e := client.Do(req)
	if e != nil {
		return ErrManagementUnavailable
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(io.LimitReader(resp.Body, 64))
	if e != nil || resp.StatusCode != 200 || string(b) != "management-ready" || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 || !bytes.Equal(resp.TLS.PeerCertificates[0].Raw, block.Bytes) {
		return errors.New("management TLS publication mismatch")
	}
	return nil
}
