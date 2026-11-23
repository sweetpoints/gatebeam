// Package probe provides bounded one-shot HTTP with a pinned connection address,
// independent HTTP Host and TLS verification name. It never follows redirects.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"gatebeam/internal/modules/deployment/application/health"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var ErrProbe = errors.New("probe refused or unhealthy")

type HTTP struct{}

func (HTTP) Check(ctx context.Context, p health.Probe) error {
	if !p.Address.IsValid() || p.Address.Port() == 0 || (p.Protocol != "http" && p.Protocol != "https") || p.HTTPHost == "" || strings.ContainsAny(p.HTTPHost, "/\\@?# \t\r\n") || !strings.HasPrefix(p.Path, "/") || strings.HasPrefix(p.Path, "//") || strings.ContainsAny(p.Path, "\r\n") {
		return ErrProbe
	}
	path, e := url.ParseRequestURI(p.Path)
	if e != nil || path.IsAbs() || path.Host != "" {
		return ErrProbe
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: p.TLSName}
	if p.Protocol == "https" {
		if p.TLSName == "" {
			return ErrProbe
		}
		if p.Trust != nil {
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(p.Trust.TrustPEM) {
				return ErrProbe
			}
			config.RootCAs = roots
		}
		if p.ClientCertificate != nil {
			cert, e := tls.X509KeyPair(p.ClientCertificate.CertificatePEM, p.ClientCertificate.KeyPEM)
			if e != nil {
				return ErrProbe
			}
			config.Certificates = []tls.Certificate{cert}
		}
	}
	if p.TLSServerNameMode != "" && p.TLSServerNameMode != "send" && p.TLSServerNameMode != "verify_only" {
		return ErrProbe
	}
	if p.TLSServerNameMode == "verify_only" {
		if p.Protocol != "https" || p.ClientCertificate == nil {
			return ErrProbe
		}
		// Go couples the ordinary SNI field and default hostname verifier.
		// Suppress only SNI, then perform the full standard chain + explicit
		// hostname verification in VerifyConnection on EVERY handshake.
		config.ServerName = ""
		config.InsecureSkipVerify = true
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return ErrProbe
			}
			intermediates := x509.NewCertPool()
			for _, cert := range state.PeerCertificates[1:] {
				intermediates.AddCert(cert)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: config.RootCAs, Intermediates: intermediates, DNSName: p.TLSName, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		}
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10, TLSHandshakeTimeout: 60 * time.Second, ResponseHeaderTimeout: 60 * time.Second, TLSClientConfig: config, DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 60 * time.Second}).DialContext(c, "tcp", p.Address.String())
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 60 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, http.MethodGet, p.Protocol+"://"+p.Address.String()+p.Path, nil)
	if e != nil {
		return ErrProbe
	}
	req.Host = p.HTTPHost
	response, e := client.Do(req)
	if e != nil {
		return ErrProbe
	}
	defer response.Body.Close()
	// Responses are consumed only up to a small constant; even an endless body
	// cannot retain a worker beyond the request deadline.
	if _, e := io.Copy(io.Discard, io.LimitReader(response.Body, 4096)); e != nil {
		return errors.Join(ErrProbe, e)
	}
	if e := ctx.Err(); e != nil {
		return errors.Join(ErrProbe, e)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return ErrProbe
	}
	return nil
}
