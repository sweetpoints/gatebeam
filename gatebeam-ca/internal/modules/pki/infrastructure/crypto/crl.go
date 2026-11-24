package pkicrypto

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	"math/big"
	"time"
)

func (s *StatusSigner) SignCRL(issuer domain.IssuerID, number int64, rows []domain.Revocation, now time.Time) ([]byte, error) {
	if issuer != s.issuer.Metadata().ID {
		return nil, status.ErrUnknownIssuer
	}
	if e := s.issuer.Validate(now); e != nil {
		return nil, e
	}
	next := now.Add(time.Hour)
	if next.After(s.issuer.Certificate.NotAfter) {
		next = s.issuer.Certificate.NotAfter
	}
	entries := make([]x509.RevocationListEntry, 0, len(rows))
	for _, r := range rows {
		serial, ok := new(big.Int).SetString(string(r.Serial), 16)
		if !ok {
			return nil, ErrIssuer
		}
		entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: r.At, ReasonCode: r.Reason})
	}
	der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: now.UTC().Truncate(time.Second), NextUpdate: next.UTC().Truncate(time.Second), RevokedCertificateEntries: entries}, s.issuer.Certificate, s.issuer.Signer)
	if e != nil {
		return nil, e
	}
	crl, e := x509.ParseRevocationList(der)
	if e != nil {
		return nil, e
	}
	if e = crl.CheckSignatureFrom(s.issuer.Certificate); e != nil {
		return nil, e
	}
	return der, nil
}

// RootCRLReader reads only public, offline-signed status. It never accepts a
// signer or root-key path. Replacing this public file supports offline renewal.
type RootCRLReader struct {
	Root *x509.Certificate
	Path string
}

func (r RootCRLReader) ReadRootCRL(ctx context.Context) ([]byte, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	der, e := readFile(r.Path, false)
	if e != nil {
		return nil, e
	}
	c, e := x509.ParseRevocationList(der)
	now := time.Now()
	if e != nil || r.Root == nil || c.CheckSignatureFrom(r.Root) != nil || c.Number == nil || c.Number.Sign() <= 0 || c.ThisUpdate.After(now) || !c.NextUpdate.After(now) || c.NextUpdate.After(r.Root.NotAfter) {
		return nil, ErrIssuer
	}

	return der, nil
}

// CheckIssuer is a startup safety check, separate from publishing a correctly
// signed root CRL (which must still be available when it revokes this issuer).
func (r RootCRLReader) CheckIssuer(ctx context.Context, issuer *x509.Certificate) error {
	der, e := r.ReadRootCRL(ctx)
	if e != nil {
		return e
	}
	list, e := x509.ParseRevocationList(der)
	if e != nil {
		return e
	}
	for _, entry := range list.RevokedCertificateEntries {
		if issuer == nil || entry.SerialNumber.Cmp(issuer.SerialNumber) == 0 {
			return ErrIssuer
		}
	}
	return nil
}
