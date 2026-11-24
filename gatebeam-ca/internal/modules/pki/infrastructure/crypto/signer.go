package pkicrypto

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/domain"
	"math/big"
	"time"
)

type OrderSigner struct {
	Issuer   Issuer
	Lifetime time.Duration
	Policies map[domain.Usage]domain.Policy
}

func (s OrderSigner) NewSerial() (domain.IssuerID, domain.Serial, error) {
	v, e := NewSerial()
	if e != nil {
		return "", "", e
	}
	return s.Issuer.Metadata().ID, domain.Serial(fmt.Sprintf("%040x", v)), nil
}
func (s OrderSigner) Sign(csr []byte, p domain.Policy, names []string, serial domain.Serial, now time.Time) (domain.IssuedCertificate, error) {
	if s.Policies != nil {
		configured, ok := s.Policies[p.Usage()]
		if !ok || configured.Authorize(names) != nil {
			return domain.IssuedCertificate{}, app.ErrBadCSR
		}
	}
	n, ok := new(big.Int).SetString(string(serial), 16)
	if !ok {
		return domain.IssuedCertificate{}, app.ErrBadCSR
	}
	lifetime := s.Lifetime
	if lifetime == 0 {
		lifetime = 24 * time.Hour
	}
	der, e := s.Issuer.SignCSR(csr, p, names, n, now, lifetime)
	if e != nil {
		return domain.IssuedCertificate{}, app.ErrBadCSR
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		return domain.IssuedCertificate{}, e
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Issuer.Certificate.Raw})...)
	return domain.IssuedCertificate{IssuerID: s.Issuer.Metadata().ID, Serial: serial, DER: der, Chain: chain, NotBefore: leaf.NotBefore, NotAfter: leaf.NotAfter}, nil
}
