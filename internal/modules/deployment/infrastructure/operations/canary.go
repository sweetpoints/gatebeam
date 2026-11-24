package operations

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"github.com/google/uuid"
	"golang.org/x/crypto/ocsp"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CanarySpec is a protected host secret, never stored in the deployment journal.
// The only configuration mutation permitted is saving an unpublished, disabled,
// explicitly named deployment-canary site's existing draft.
type CanarySpec struct {
	SessionCookie                 string `json:"session_cookie"`
	CSRFToken                     string `json:"csrf_token"`
	SiteID                        string `json:"site_id"`
	BusinessHost                  string `json:"business_host"`
	BusinessPath                  string `json:"business_path"`
	BusinessSHA256                string `json:"business_sha256"`
	BusinessTrustFile             string `json:"business_trust_file,omitempty"`
	BusinessClientCertificateFile string `json:"business_client_certificate_file,omitempty"`
	BusinessClientKeyFile         string `json:"business_client_key_file,omitempty"`
}

func (h LocalHost) canarySpec() (CanarySpec, error) {
	var s CanarySpec
	p := h.Configuration.Node.CanaryFile
	st, e := os.Lstat(p)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 16384 || filepath.Clean(p) != p {
		return s, ErrOperation
	}
	raw, e := os.ReadFile(p)
	if e != nil || json.Unmarshal(raw, &s) != nil || s.SessionCookie == "" || s.CSRFToken == "" || uuid.Validate(s.SiteID) != nil {
		return s, ErrOperation
	}
	if !strings.HasPrefix(s.BusinessPath, "/") || strings.HasPrefix(s.BusinessPath, "//") || s.BusinessHost == "" || strings.ContainsAny(s.BusinessHost, "/:@\\ \r\n") || len(s.BusinessSHA256) != 64 {
		return s, ErrOperation
	}
	if _, e = hex.DecodeString(s.BusinessSHA256); e != nil {
		return s, ErrOperation
	}
	return s, nil
}
func requestCanary(ctx context.Context, client *http.Client, method, url, origin string, s CanarySpec, body []byte, id string) ([]byte, error) {
	r, e := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if e != nil {
		return nil, ErrOperation
	}
	r.AddCookie(&http.Cookie{Name: "__Host-gatebeam", Value: s.SessionCookie})
	if method != "GET" {
		r.Header.Set("Origin", origin)
		r.Header.Set("X-CSRF-Token", s.CSRFToken)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", id)
	}
	response, e := client.Do(r)
	if e != nil {
		return nil, ErrOperation
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(raw) > 1<<20 || response.StatusCode != 200 {
		return nil, ErrOperation
	}
	return raw, nil
}
func VerifyManagementCanary(ctx context.Context, c *http.Client, base, origin string, s CanarySpec, write bool, id string) error {
	if _, e := requestCanary(ctx, c, "GET", base+"/auth/session", origin, s, nil, ""); e != nil {
		return e
	}
	raw, e := requestCanary(ctx, c, "GET", base+"/sites/"+s.SiteID, origin, s, nil, "")
	if e != nil {
		return e
	}
	var site struct {
		Name              string
		Revision          int64
		Draft             json.RawMessage
		Published         json.RawMessage
		PublishedRevision int64 `json:"published_revision"`
	}
	if json.Unmarshal(raw, &site) != nil || !strings.HasPrefix(site.Name, "gatebeam-upgrade-canary-") || site.Revision < 1 || site.PublishedRevision != 0 {
		return ErrOperation
	}
	var draft struct{ Enabled bool }
	if len(site.Draft) == 0 || json.Unmarshal(site.Draft, &draft) != nil || draft.Enabled {
		return ErrOperation
	}
	if !write {
		return nil
	}
	body, _ := json.Marshal(map[string]any{"config": site.Draft, "expected_revision": site.Revision})
	_, e = requestCanary(ctx, c, "PUT", base+"/sites/"+s.SiteID+"/draft", origin, s, body, id)
	return e
}
func (h LocalHost) canaryClient(host, port string, roots []byte, pair *tls.Certificate) (*http.Client, error) {
	pool, e := x509.SystemCertPool()
	if e != nil {
		pool = x509.NewCertPool()
	}
	if len(roots) > 0 && !pool.AppendCertsFromPEM(roots) {
		return nil, ErrOperation
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: host, MinVersion: tls.VersionTLS12}
	if pair != nil {
		cfg.Certificates = []tls.Certificate{*pair}
	}
	address := net.JoinHostPort(h.Configuration.Node.PrivateAddress, port)
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: cfg, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
	}}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}
func (h LocalHost) functionalCanary(ctx context.Context, kind, id string) error {
	spec, e := h.canarySpec()
	if e != nil {
		return e
	}
	edge, e := h.config("nginx")
	if e != nil {
		return e
	}
	if kind == "verify-private" {
		return h.statusCanary(ctx)
	}
	host, port := edge.ManagementDomain, "443"
	var pair *tls.Certificate
	trust, e := h.fileInRole("nginx", edge.ManagementTrustFile)
	if e != nil {
		return e
	}
	if kind == "verify-api" {
		host, port = edge.ManagementAPIName, "9443"
		trust, e = h.fileInRole("nginx", edge.ManagementAPITrustFile)
		if e != nil {
			return e
		}
		cert, e := h.fileInRole("nginx", edge.ManagementAPIClientCertificateFile)
		if e != nil {
			return e
		}
		key, e := h.fileInRole("nginx", edge.ManagementAPIClientKeyFile)
		if e != nil {
			return e
		}
		p, e := tls.X509KeyPair(cert, key)
		clear(key)
		if e != nil {
			return ErrOperation
		}
		pair = &p
	}
	client, e := h.canaryClient(host, port, trust, pair)
	if e != nil {
		return e
	}
	if e = VerifyManagementCanary(ctx, client, "https://"+host, "https://"+edge.ManagementDomain, spec, kind == "verify-api", id); e != nil {
		return e
	}
	if kind == "verify-api" {
		return h.control(ctx, "background-jobs", "/capabilities/verify", struct{}{}, nil)
	}
	var businessTrust []byte
	if spec.BusinessTrustFile != "" {
		businessTrust, e = os.ReadFile(spec.BusinessTrustFile)
		if e != nil || len(businessTrust) > 1<<20 {
			return ErrOperation
		}
	}
	var businessPair *tls.Certificate
	if spec.BusinessClientCertificateFile != "" || spec.BusinessClientKeyFile != "" {
		st, e := os.Lstat(spec.BusinessClientKeyFile)
		if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<20 {
			return ErrOperation
		}
		p, e := tls.LoadX509KeyPair(spec.BusinessClientCertificateFile, spec.BusinessClientKeyFile)
		if e != nil {
			return ErrOperation
		}
		businessPair = &p
	}
	business, e := h.canaryClient(spec.BusinessHost, "443", businessTrust, businessPair)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, "GET", "https://"+spec.BusinessHost+spec.BusinessPath, nil)
	if e != nil {
		return ErrOperation
	}
	response, e := business.Do(req)
	if e != nil {
		return ErrOperation
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	sum := sha256.Sum256(raw)
	if e != nil || len(raw) > 1<<20 || response.StatusCode != 200 || hex.EncodeToString(sum[:]) != spec.BusinessSHA256 {
		return ErrOperation
	}
	return nil
}
func caProbeURL(raw, scheme, path string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != scheme || u.Hostname() == "" || raw != scheme+"://"+u.Host {
		return "", ErrOperation
	}
	u.Path = path
	return u.String(), nil
}

func (h LocalHost) externalCADirectory(ctx context.Context) error {
	cfg, err := h.config("management")
	if err != nil {
		return err
	}
	address, err := caProbeURL(cfg.CAOrigin, "https", "/acme/server/directory")
	if err != nil {
		return err
	}
	trust, err := h.fileInRole("management", cfg.CertificateACMETransportTrustFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(trust) {
		return ErrOperation
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var directory struct {
		NewNonce string `json:"newNonce"`
		NewOrder string `json:"newOrder"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&directory) != nil || directory.NewNonce == "" || directory.NewOrder == "" {
		return ErrOperation
	}
	return nil
}

func (h LocalHost) statusCanary(ctx context.Context) error {
	cfg, e := h.config("management")
	if e != nil {
		return e
	}
	data, e := h.fileInRole("management", cfg.CertificateStatusTrustFile)
	if e != nil {
		return e
	}
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(data)) > 0 && len(certs) < 20 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return ErrOperation
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !cert.IsCA {
			return ErrOperation
		}
		certs = append(certs, cert)
		data = rest
	}
	var root, issuer *x509.Certificate
	for _, child := range certs {
		if child.CheckSignatureFrom(child) == nil {
			continue
		}
		for _, parent := range certs {
			if parent.CheckSignatureFrom(parent) == nil && child.CheckSignatureFrom(parent) == nil {
				root, issuer = parent, child
				break
			}
		}
		if issuer != nil {
			break
		}
	}
	if issuer == nil {
		return ErrOperation
	}
	request, e := ocsp.CreateRequest(issuer, root, nil)
	if e != nil {
		return ErrOperation
	}
	address, e := caProbeURL(cfg.CAStatusOrigin, "http", "/ocsp")
	if e != nil {
		return e
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "POST", address, bytes.NewReader(request))
	if e != nil {
		return ErrOperation
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	response, e := client.Do(req)
	if e != nil {
		return ErrOperation
	}
	defer response.Body.Close()
	raw, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(raw) > 65536 || response.StatusCode != 200 {
		return ErrOperation
	}
	status, e := ocsp.ParseResponseForCert(raw, issuer, root)
	now := time.Now()
	if e != nil || status.Status != ocsp.Good || status.ThisUpdate.After(now) || !now.Before(status.NextUpdate) {
		return ErrOperation
	}
	return nil
}
