package nginx

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/platform/dnsserver"
	"strings"
)

// crl binds a complete, issuer-signed current CRL set to the immutable trust
// revision. OpenSSL checks every issuer in a chain, including intermediate CAs.
func (b *builder) crl(ref *app.MaterialRef) (string, error) {
	if ref == nil || b.runtime.Now.IsZero() {
		return "", ErrInvalid
	}
	m, ok := b.runtime.Materials[ref.ID]
	if !ok || m.Revision != ref.Revision || len(m.TrustPEM) > 1<<20 || len(m.CRLPEM) == 0 || len(m.CRLPEM) > 1<<20 {
		return "", ErrInvalid
	}
	issuers := map[string]*x509.Certificate{}
	rest := bytes.TrimSpace(m.TrustPEM)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" {
			return "", ErrInvalid
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !cert.IsCA || b.runtime.Now.Before(cert.NotBefore) || !b.runtime.Now.Before(cert.NotAfter) {
			return "", ErrInvalid
		}
		// Subject DNs are not key identities: a standard CA rollover may
		// retain the DN while both old and new signing keys remain trusted.
		key := string(cert.RawSubject) + string(cert.RawSubjectPublicKeyInfo)
		if _, exists := issuers[key]; exists {
			return "", ErrInvalid
		}
		issuers[key] = cert
		if len(issuers) > 20 {
			return "", ErrInvalid
		}
		rest = bytes.TrimSpace(next)
	}
	if len(issuers) == 0 {
		return "", ErrInvalid
	}
	seen := map[string]bool{}
	rest = bytes.TrimSpace(m.CRLPEM)
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "X509 CRL" {
			return "", ErrInvalid
		}
		list, e := x509.ParseRevocationList(block.Bytes)
		if e != nil {
			return "", ErrInvalid
		}
		if list.ThisUpdate.IsZero() || list.NextUpdate.IsZero() || b.runtime.Now.Before(list.ThisUpdate) || !b.runtime.Now.Before(list.NextUpdate) || !list.ThisUpdate.Before(list.NextUpdate) {
			return "", ErrInvalid
		}
		matched := ""
		for key, issuer := range issuers {
			if !bytes.Equal(list.RawIssuer, issuer.RawSubject) || (len(list.AuthorityKeyId) > 0 && !bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId)) || list.CheckSignatureFrom(issuer) != nil {
				continue
			}
			if matched != "" || seen[key] {
				return "", ErrInvalid
			}
			matched = key
		}
		if matched == "" {
			return "", ErrInvalid
		}
		seen[matched] = true
		rest = bytes.TrimSpace(next)
	}
	if len(seen) != len(issuers) {
		return "", ErrInvalid
	}
	path := "materials/" + token(ref.ID+fmt.Sprint("/", ref.Revision, "/crl")) + ".crl"
	b.files[path] = append([]byte{}, m.CRLPEM...)
	return path, nil
}
func validateOCSP(m edge.Material, r edge.RuntimeState) error {
	p := m.OCSP
	dns := r.OCSPResolver
	if p == nil || !version.MatchString(p.Generation) || r.Now.IsZero() || (p.ValidUntil.IsZero() || (r.OCSPResponder == "" && !r.Now.Before(p.ValidUntil))) || len(p.ResponderNames) == 0 || len(p.ResponderNames) > 20 || dns == nil || !version.MatchString(dns.Generation) || len(dns.Servers) == 0 || len(dns.Servers) > 3 || dns.TimeoutSeconds < 1 || dns.TimeoutSeconds > 5 || dns.ValidForSeconds < 1 || dns.ValidForSeconds > 300 || r.TLSHandshakeTimeoutSeconds < 1 || r.TLSHandshakeTimeoutSeconds > 30 {
		return ErrInvalid
	}
	for _, name := range p.ResponderNames {
		if !validName(name) {
			return ErrInvalid
		}
	}
	for _, server := range dns.Servers {
		if !dnsserver.Valid(server) {
			return ErrInvalid
		}
	}
	return nil
}
func writeOCSPResolver(w *strings.Builder, r edge.RuntimeState) {
	fmt.Fprintf(w, "resolver")
	for _, server := range r.OCSPResolver.Servers {
		fmt.Fprintf(w, " %s", server)
	}
	fmt.Fprintf(w, " valid=%ds;\nresolver_timeout %ds;\n", r.OCSPResolver.ValidForSeconds, r.OCSPResolver.TimeoutSeconds)
}
