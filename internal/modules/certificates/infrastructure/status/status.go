// Package status verifies standard OCSP/CRL responses under operator-owned policy.
package status

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/platform/dnsserver"
	"golang.org/x/crypto/ocsp"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"time"
)

var ErrStatus = errors.New("trusted standard status evidence unavailable")

type Profile struct {
	ID              string            `json:"id"`
	Fingerprints    []string          `json:"fingerprints"`
	CRLURLs         map[string]string `json:"crl_urls"`
	OCSPURLs        map[string]string `json:"ocsp_urls"`
	AllowedNetworks []string          `json:"allowed_networks"`
	ResolverServers []string          `json:"resolver_servers"`
}
type bound struct {
	profile Profile
	digest  string
	client  *http.Client
}
type Client struct{ profiles map[string]bound }

func digest(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func New(profiles []Profile) (*Client, error) {
	c := &Client{profiles: map[string]bound{}}
	for _, p := range profiles {
		if p.ID == "" || len(p.Fingerprints) == 0 || len(p.Fingerprints) > 20 || len(p.ResolverServers) < 1 || len(p.ResolverServers) > 3 || len(p.AllowedNetworks) == 0 || len(p.AllowedNetworks) > 20 {
			return nil, ErrStatus
		}
		if _, ok := c.profiles[p.ID]; ok {
			return nil, ErrStatus
		}
		prefixes := []netip.Prefix{}
		for _, raw := range p.AllowedNetworks {
			v, e := netip.ParsePrefix(raw)
			if e != nil || v.Bits() == 0 {
				return nil, ErrStatus
			}
			prefixes = append(prefixes, v)
		}
		servers := []netip.AddrPort{}
		for _, raw := range p.ResolverServers {
			v, e := netip.ParseAddrPort(raw)
			if e != nil || !dnsserver.Valid(v) {
				return nil, ErrStatus
			}
			servers = append(servers, v)
		}
		hosts := map[string]bool{}
		for _, fp := range p.Fingerprints {
			for _, raw := range []string{p.CRLURLs[fp], p.OCSPURLs[fp]} {
				u, e := url.Parse(raw)
				if e != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
					return nil, ErrStatus
				}
				hosts[u.Hostname()] = true
			}
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, servers[0].String())
		}}
		transport := &http.Transport{ResponseHeaderTimeout: 2 * time.Second, TLSHandshakeTimeout: 2 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, e := net.SplitHostPort(address)
			if e != nil || !hosts[host] {
				return nil, ErrStatus
			}
			ips, e := resolver.LookupNetIP(ctx, "ip", host)
			if e != nil || len(ips) == 0 || len(ips) > 16 {
				return nil, ErrStatus
			}
			for _, ip := range ips {
				allowed := false
				for _, p := range prefixes {
					if p.Contains(ip.Unmap()) {
						allowed = true
					}
				}
				if !allowed {
					return nil, ErrStatus
				}
			}
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
		}}
		c.profiles[p.ID] = bound{p, digest(p), &http.Client{Timeout: 4 * time.Second, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	}
	return c, nil
}
func (c *Client) ProfileDigest(id string) string { return c.profiles[id].digest }
func fetch(ctx context.Context, client *http.Client, address string, body []byte) ([]byte, error) {
	method := http.MethodGet
	if body != nil {
		method = http.MethodPost
	}
	req, e := http.NewRequestWithContext(ctx, method, address, bytes.NewReader(body))
	if e != nil {
		return nil, ErrStatus
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/ocsp-request")
	}
	response, e := client.Do(req)
	if e != nil {
		return nil, ErrStatus
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, ErrStatus
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
	if e != nil || len(data) > 1<<20 {
		return nil, ErrStatus
	}
	return data, nil
}
func parsePEM(data []byte) ([]*x509.Certificate, error) {
	out := []*x509.Certificate{}
	for rest := bytes.TrimSpace(data); len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, ErrStatus
		}
		v, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, ErrStatus
		}
		out = append(out, v)
		rest = bytes.TrimSpace(next)
	}
	return out, nil
}
func fingerprint(c *x509.Certificate) string {
	h := sha256.Sum256(c.Raw)
	return hex.EncodeToString(h[:])
}
func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// Attest establishes responder readiness using signed Unknown for synthetic
// serials. It never asserts that an actual client certificate is Good. Actual
// intermediate certificates are queried separately and MUST be Good.
func (c *Client) Attest(ctx context.Context, trust app.TrustBundle, data []byte, now time.Time) (out app.StatusAttestation, err error) {
	b, ok := c.profiles[trust.StatusProfile]
	if !ok {
		return out, ErrStatus
	}
	expected, actual := slices.Clone(trust.Fingerprints), slices.Clone(b.profile.Fingerprints)
	sort.Strings(expected)
	sort.Strings(actual)
	if !slices.Equal(expected, actual) {
		return out, ErrStatus
	}
	certs, e := parsePEM(data)
	if e != nil || len(certs) != len(expected) {
		return out, ErrStatus
	}
	out = app.StatusAttestation{ProfileDigest: b.digest, ValidUntil: now.Add(5 * time.Minute), ResolverServers: b.profile.ResolverServers, UnknownResponderReady: true}
	issuers := map[string]*x509.Certificate{}
	crls := map[string]*x509.RevocationList{}
	names := map[string]bool{}
	for _, issuer := range certs {
		fp := fingerprint(issuer)
		if !slices.Contains(expected, fp) || issuers[fp] != nil || !issuer.IsCA || now.Before(issuer.NotBefore) || !now.Before(issuer.NotAfter) {
			return app.StatusAttestation{}, ErrStatus
		}
		issuers[fp] = issuer
		out.ValidUntil = earlier(out.ValidUntil, issuer.NotAfter)
		raw, e := fetch(ctx, b.client, b.profile.CRLURLs[fp], nil)
		if e != nil {
			return app.StatusAttestation{}, e
		}
		list, e := x509.ParseRevocationList(raw)
		if e != nil || list.CheckSignatureFrom(issuer) != nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) || (len(list.AuthorityKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId)) || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) || !list.ThisUpdate.Before(list.NextUpdate) {
			return app.StatusAttestation{}, ErrStatus
		}
		out.ValidUntil = earlier(out.ValidUntil, list.NextUpdate)
		out.CRLPEM = append(out.CRLPEM, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})...)
		crls[fp] = list
		serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
		if e != nil {
			return app.StatusAttestation{}, e
		}
		probe := &x509.Certificate{SerialNumber: serial}
		until, e := checkOCSP(ctx, b.client, b.profile.OCSPURLs[fp], probe, issuer, ocsp.Unknown, now)
		if e != nil {
			return app.StatusAttestation{}, e
		}
		out.ValidUntil = earlier(out.ValidUntil, until)
		u, _ := url.Parse(b.profile.OCSPURLs[fp])
		names[u.Hostname()] = true
	}
	for _, cert := range certs {
		if cert.CheckSignatureFrom(cert) == nil {
			continue
		}
		var parent *x509.Certificate
		for _, candidate := range certs {
			if bytes.Equal(cert.RawIssuer, candidate.RawSubject) && cert.CheckSignatureFrom(candidate) == nil {
				parent = candidate
				break
			}
		}
		if parent == nil {
			return app.StatusAttestation{}, ErrStatus
		}
		fp := fingerprint(parent)
		for _, entry := range crls[fp].RevokedCertificateEntries {
			if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return app.StatusAttestation{}, ErrStatus
			}
		}
		endpoint := b.profile.OCSPURLs[fp]
		if !slices.Contains(cert.OCSPServer, endpoint) {
			return app.StatusAttestation{}, ErrStatus
		}
		until, e := checkOCSP(ctx, b.client, endpoint, cert, parent, ocsp.Good, now)
		if e != nil {
			return app.StatusAttestation{}, e
		}
		out.ValidUntil = earlier(out.ValidUntil, until)
	}
	for name := range names {
		out.ResponderNames = append(out.ResponderNames, name)
	}
	sort.Strings(out.ResponderNames)
	out.Generation = digest(out)
	return out, nil
}

// Standard ASN.1 CertID extraction supplements x/crypto's signature validation:
// ParseResponseForCert matches serial but does not compare both issuer hashes.
type certID struct {
	Algorithm         pkix.AlgorithmIdentifier
	NameHash, KeyHash []byte
	Serial            *big.Int
}
type single struct {
	ID         certID
	Status     asn1.RawValue
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"explicit,tag:0,optional,generalized"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type responseData struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,default:0,explicit,tag:0"`
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []single
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

func checkOCSP(ctx context.Context, client *http.Client, endpoint string, cert, issuer *x509.Certificate, want int, now time.Time) (time.Time, error) {
	request, e := ocsp.CreateRequest(cert, issuer, nil)
	if e != nil {
		return time.Time{}, ErrStatus
	}
	req, e := ocsp.ParseRequest(request)
	if e != nil {
		return time.Time{}, ErrStatus
	}
	started := time.Now()
	raw, e := fetch(ctx, client, endpoint, request)
	now = now.Add(time.Since(started))
	if e != nil {
		return time.Time{}, e
	}
	response, e := ocsp.ParseResponseForCert(raw, cert, issuer)
	if e != nil || response.Status != want || now.Before(response.ThisUpdate) || !now.Before(response.NextUpdate) || !response.ThisUpdate.Before(response.NextUpdate) || response.ProducedAt.After(now.Add(time.Minute)) {
		return time.Time{}, ErrStatus
	}
	var tbs responseData
	rest, e := asn1.Unmarshal(response.TBSResponseData, &tbs)
	if e != nil || len(rest) != 0 || len(tbs.Responses) != 1 {
		return time.Time{}, ErrStatus
	}
	id := tbs.Responses[0].ID
	if id.Serial.Cmp(req.SerialNumber) != 0 || !bytes.Equal(id.NameHash, req.IssuerNameHash) || !bytes.Equal(id.KeyHash, req.IssuerKeyHash) || response.IssuerHash != req.HashAlgorithm {
		return time.Time{}, ErrStatus
	}
	signer := response.Certificate
	if signer == nil {
		signer = issuer
	}
	if len(response.RawResponderName) > 0 {
		if !bytes.Equal(response.RawResponderName, signer.RawSubject) {
			return time.Time{}, ErrStatus
		}
	} else {
		var public struct {
			Algorithm pkix.AlgorithmIdentifier
			Key       asn1.BitString
		}
		rest, e := asn1.Unmarshal(signer.RawSubjectPublicKeyInfo, &public)
		if e != nil || len(rest) != 0 {
			return time.Time{}, ErrStatus
		}
		hash := sha1.Sum(public.Key.RightAlign())
		if !bytes.Equal(response.ResponderKeyHash, hash[:]) {
			return time.Time{}, ErrStatus
		}
	}
	// Some responders (including Go x/crypto/ocsp) round ProducedAt to
	// the minute while ThisUpdate retains seconds. Freshness still uses
	// the original ThisUpdate and NextUpdate values.
	if response.ProducedAt.IsZero() || response.ProducedAt.Before(response.ThisUpdate.Truncate(time.Minute)) {
		return time.Time{}, ErrStatus
	}
	for _, extension := range tbs.Extensions {
		if extension.Critical {
			return time.Time{}, ErrStatus
		}
	}
	if signer := response.Certificate; signer != nil {
		if signer.CheckSignatureFrom(issuer) != nil || !slices.Contains(signer.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) || (signer.KeyUsage != 0 && signer.KeyUsage&x509.KeyUsageDigitalSignature == 0) || now.Before(signer.NotBefore) || !now.Before(signer.NotAfter) {
			return time.Time{}, ErrStatus
		}
		return earlier(response.NextUpdate, signer.NotAfter), nil
	}
	return response.NextUpdate, nil
}
