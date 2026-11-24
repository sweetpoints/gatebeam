package pkicrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"sync"
	"time"
)

// StatusSigner holds the online intermediate only. OCSP responses use a separate
// short-lived delegated key; its replacement never requires the offline root.
type StatusSigner struct {
	issuer    Issuer
	mu        sync.Mutex
	responder *x509.Certificate
	key       crypto.Signer
}

func NewStatusSigner(i Issuer) *StatusSigner { return &StatusSigner{issuer: i} }
func hashAlgorithm(name string) crypto.Hash {
	switch name {
	case "SHA-1":
		return crypto.SHA1
	case "SHA-256":
		return crypto.SHA256
	case "SHA-384":
		return crypto.SHA384
	case "SHA-512":
		return crypto.SHA512
	}
	return 0
}
func (s *StatusSigner) MatchIssuer(id status.CertID) (domain.IssuerID, error) {
	h := hashAlgorithm(id.Hash)
	if h == 0 || !h.Available() || s.issuer.Certificate == nil {
		return "", status.ErrUnknownIssuer
	}
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		Key       asn1.BitString
	}
	if rest, e := asn1.Unmarshal(s.issuer.Certificate.RawSubjectPublicKeyInfo, &spki); e != nil || len(rest) != 0 {
		return "", status.ErrUnknownIssuer
	}
	sum := h.New()
	sum.Write(s.issuer.Certificate.RawSubject)
	if !bytes.Equal(sum.Sum(nil), id.NameHash) {
		return "", status.ErrUnknownIssuer
	}
	sum.Reset()
	sum.Write(spki.Key.RightAlign())
	if !bytes.Equal(sum.Sum(nil), id.KeyHash) {
		return "", status.ErrUnknownIssuer
	}
	return s.issuer.Metadata().ID, nil
}
func (s *StatusSigner) CertificateID(der []byte) (domain.IssuerID, domain.Serial, error) {
	c, e := x509.ParseCertificate(der)
	if e != nil || c.IsCA || c.CheckSignatureFrom(s.issuer.Certificate) != nil {
		return "", "", ErrCSR
	}
	if c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 159 {
		return "", "", ErrCSR
	}
	return s.issuer.Metadata().ID, domain.Serial(fmt.Sprintf("%040x", c.SerialNumber)), nil
}
func (s *StatusSigner) MatchCertificateKey(der, key []byte) bool {
	c, e := x509.ParseCertificate(der)
	if e != nil {
		return false
	}
	var jwk jose.JSONWebKey
	if json.Unmarshal(key, &jwk) != nil || !jwk.IsPublic() || !jwk.Valid() {
		return false
	}
	pub, e := x509.MarshalPKIXPublicKey(jwk.Key)
	return e == nil && bytes.Equal(pub, c.RawSubjectPublicKeyInfo)
}
func (s *StatusSigner) delegated(now time.Time) error {
	if s.responder != nil && s.responder.NotAfter.After(now.Add(10*time.Minute)) {
		return nil
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return e
	}
	serial, e := NewSerial()
	if e != nil {
		return e
	}
	until := now.Add(24 * time.Hour)
	if until.After(s.issuer.Certificate.NotAfter) {
		until = s.issuer.Certificate.NotAfter
	}
	if !until.After(now.Add(10 * time.Minute)) {
		return ErrIssuer
	}
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Gatebeam OCSP responder"}, NotBefore: now.Add(-time.Minute), NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, s.issuer.Certificate, &key.PublicKey, s.issuer.Signer)
	if e != nil {
		return e
	}
	cert, e := x509.ParseCertificate(der)
	if e != nil {
		return e
	}
	s.responder, s.key = cert, key
	return nil
}
func (s *StatusSigner) SignOCSP(id status.CertID, r status.Record, now time.Time) (status.SignedResponse, error) {
	if _, e := s.MatchIssuer(id); e != nil {
		return status.SignedResponse{}, e
	}
	if e := s.issuer.Validate(now); e != nil {
		return status.SignedResponse{}, e
	}
	serial, ok := new(big.Int).SetString(string(id.Serial), 16)
	if !ok || serial.Sign() <= 0 || serial.BitLen() > 159 {
		return status.SignedResponse{}, ErrCSR
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.delegated(now); e != nil {
		return status.SignedResponse{}, e
	}
	next := now.Add(5 * time.Minute)
	tmpl := ocsp.Response{SerialNumber: serial, ThisUpdate: now.UTC().Truncate(time.Second), NextUpdate: next.UTC().Truncate(time.Second), Certificate: s.responder, IssuerHash: hashAlgorithm(id.Hash)}
	switch r.State {
	case domain.StatusGood:
		tmpl.Status = ocsp.Good
	case domain.StatusUnknown:
		tmpl.Status = ocsp.Unknown
	case domain.StatusRevoked:
		tmpl.Status = ocsp.Revoked
		tmpl.RevokedAt = r.Revocation.At
		tmpl.RevocationReason = r.Revocation.Reason
	default:
		return status.SignedResponse{}, ErrIssuer
	}
	der, e := ocsp.CreateResponse(s.issuer.Certificate, s.responder, tmpl, s.key)
	if e != nil {
		return status.SignedResponse{}, e
	}
	// Validate both delegated authorization and standard response signature. The
	// library's response parser alone is not an EKU/path/time policy validator.
	roots := x509.NewCertPool()
	roots.AddCert(s.issuer.Chain[0])
	ints := x509.NewCertPool()
	ints.AddCert(s.issuer.Certificate)
	if _, e = s.responder.Verify(x509.VerifyOptions{Roots: roots, Intermediates: ints, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}); e != nil {
		return status.SignedResponse{}, e
	}
	if _, e = ocsp.ParseResponse(der, s.issuer.Certificate); e != nil {
		return status.SignedResponse{}, e
	}
	return status.SignedResponse{DER: der, CredentialDER: s.responder.Raw, CredentialSerial: domain.Serial(fmt.Sprintf("%040x", s.responder.SerialNumber))}, nil
}
