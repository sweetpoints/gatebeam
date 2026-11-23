// Package crypto validates standard PEM material and generates local private keys.
package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/domain"
	"slices"
	"time"
)

type Crypto struct{ Roots []byte }

func (Crypto) NewID() (string, error) {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", e
	}
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
func (Crypto) Digest(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
func (Crypto) NewAccountKey() ([]byte, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, e
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}
func certificates(data []byte) ([]*x509.Certificate, error) {
	if len(data) == 0 || len(data) > 1<<20 {
		return nil, domain.ErrInvalid
	}
	out := []*x509.Certificate{}
	for rest := bytes.TrimSpace(data); len(rest) > 0; {
		block, next := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) > 0 {
			return nil, domain.ErrInvalid
		}
		cert, e := x509.ParseCertificate(block.Bytes)
		if e != nil {
			return nil, domain.ErrInvalid
		}
		out = append(out, cert)
		if len(out) > 20 {
			return nil, domain.ErrInvalid
		}
		rest = bytes.TrimSpace(next)
	}
	return out, nil
}
func (c Crypto) Inspect(s application.Spec, certPEM, keyPEM []byte, now time.Time, trustPEM []byte) (application.Version, error) {
	v := application.Version{}
	if s.Validate() != nil || len(keyPEM) > 1<<20 {
		return v, domain.ErrInvalid
	}
	chain, e := certificates(certPEM)
	if e != nil {
		return v, e
	}
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil || len(pair.Certificate) == 0 {
		return v, domain.ErrInvalid
	}
	leaf := chain[0]
	if leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return v, domain.ErrInvalid
	}
	want := x509.ExtKeyUsageServerAuth
	if s.Purpose == "clientAuth" {
		want = x509.ExtKeyUsageClientAuth
	}
	if !slices.Contains(leaf.ExtKeyUsage, want) {
		return v, domain.ErrInvalid
	}
	names, expected := slices.Clone(leaf.DNSNames), slices.Clone(s.Names)
	slices.Sort(names)
	slices.Sort(expected)
	if !slices.Equal(names, expected) || len(leaf.IPAddresses) > 0 || len(leaf.URIs) > 0 || len(leaf.EmailAddresses) > 0 {
		return v, domain.ErrInvalid
	}
	roots, _ := x509.SystemCertPool()
	if roots == nil {
		roots = x509.NewCertPool()
	}
	if len(c.Roots) > 0 && !roots.AppendCertsFromPEM(c.Roots) {
		return v, domain.ErrInvalid
	}
	if s.TrustID != "" {
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(trustPEM) {
			return v, domain.ErrInvalid
		}
	}
	intermediates := x509.NewCertPool()
	for i, cert := range chain {
		if i > 0 {
			intermediates.AddCert(cert)
		}
		if s.TrustID == "" && s.Method == "import" && cert.CheckSignatureFrom(cert) == nil {
			roots.AddCert(cert)
		}
	}
	chains, e := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{want}})
	if e != nil {
		return v, domain.ErrInvalid
	}
	issuer := leaf
	if len(chains) > 0 && len(chains[0]) > 1 {
		issuer = chains[0][1]
	}
	return application.Version{IssuerKeyFingerprint: c.Digest(issuer.RawSubjectPublicKeyInfo), LeafFingerprint: c.Digest(leaf.Raw), Serial: fmt.Sprintf("%040x", leaf.SerialNumber), Names: expected, Purpose: s.Purpose, Issuer: c.Digest(issuer.Raw), NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter, Digest: c.Digest(certPEM), Automatic: s.Automatic()}, nil
}
func (c Crypto) InspectTrust(purpose string, data []byte, now time.Time) ([]string, error) {
	if purpose != "serverAuth" && purpose != "clientAuth" {
		return nil, domain.ErrInvalid
	}
	certs, e := certificates(data)
	if e != nil {
		return nil, e
	}
	out := []string{}
	for _, cert := range certs {
		if !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, domain.ErrInvalid
		}
		out = append(out, c.Digest(cert.Raw))
	}
	slices.Sort(out)
	return out, nil
}

func (Crypto) Covers(data []byte, names []string) error {
	certs, e := certificates(data)
	if e != nil {
		return e
	}
	for _, name := range names {
		if certs[0].VerifyHostname(name) != nil {
			return domain.ErrInvalid
		}
	}
	return nil
}
