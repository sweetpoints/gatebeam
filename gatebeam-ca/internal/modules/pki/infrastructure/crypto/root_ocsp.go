package pkicrypto

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/secrets"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"slices"
	"time"
)

// RootStatus contains only a root-delegated OCSP key, never a root CA signer.
// The delegated certificate is issued offline and cannot renew itself online.
type RootStatus struct {
	Root, Intermediate, Credential *x509.Certificate
	key                            crypto.Signer
	CRL                            RootCRLReader
}

func LoadRootStatus(issuer Issuer, certificateFile, keyFile, identityFile, crlFile string) (*RootStatus, error) {
	if e := issuer.Validate(time.Now()); e != nil {
		return nil, e
	}
	b, e := readFile(certificateFile, false)
	if e != nil {
		return nil, e
	}
	cert, e := parseCertificate(b)
	if e != nil {
		return nil, e
	}
	cipher, e := readFile(keyFile, true)
	if e != nil {
		return nil, e
	}
	secret, e := secrets.New(identityFile)
	if e != nil {
		return nil, e
	}
	plain, e := secret.Open("pki-root-ocsp", cipher)
	if e != nil {
		return nil, ErrIssuer
	}
	defer clear(plain)
	key, e := parseKey(plain)
	if e != nil {
		return nil, e
	}
	s := &RootStatus{Root: issuer.Chain[0], Intermediate: issuer.Certificate, Credential: cert, key: key, CRL: RootCRLReader{Root: issuer.Chain[0], Path: crlFile}}
	if e = s.Validate(time.Now()); e != nil {
		return nil, e
	}
	return s, nil
}
func certificateID(c *x509.Certificate) domain.IssuerID {
	h := sha256.Sum256(c.Raw)
	return domain.IssuerID(hex.EncodeToString(h[:]))
}
func (s *RootStatus) KnownIssuerID() domain.IssuerID { return certificateID(s.Intermediate) }
func (s *RootStatus) RootMetadata() domain.Issuer {
	id := certificateID(s.Root)
	return domain.Issuer{ID: id, Fingerprint: string(id), NotBefore: s.Root.NotBefore, NotAfter: s.Root.NotAfter}
}
func (s *RootStatus) Validate(now time.Time) error {
	c := s.Credential
	root := s.Root
	if c == nil || root == nil || s.Intermediate == nil || s.key == nil || c.SerialNumber == nil || c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 159 || c.IsCA || !c.BasicConstraintsValid || c.KeyUsage != x509.KeyUsageDigitalSignature || !slices.Equal(c.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}) || len(c.UnknownExtKeyUsage) > 0 || len(c.UnhandledCriticalExtensions) > 0 || now.Before(c.NotBefore) || !now.Before(c.NotAfter) || c.NotAfter.After(root.NotAfter) || c.CheckSignatureFrom(root) != nil || bytes.Equal(c.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) || bytes.Equal(c.RawSubjectPublicKeyInfo, s.Intermediate.RawSubjectPublicKeyInfo) {
		return ErrIssuer
	}
	pub, e := x509.MarshalPKIXPublicKey(s.key.Public())
	if e != nil || !bytes.Equal(pub, c.RawSubjectPublicKeyInfo) {
		return ErrIssuer
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, e = c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}); e != nil {
		return ErrIssuer
	}
	return nil
}
func (s *RootStatus) MatchIssuer(id status.CertID) error {
	_, e := (&StatusSigner{issuer: Issuer{Certificate: s.Root}}).MatchIssuer(id)
	return e
}
func (s *RootStatus) Response(ctx context.Context, id status.CertID, registered []byte, now time.Time) (status.RootResponse, error) {
	if e := s.MatchIssuer(id); e != nil {
		return status.RootResponse{}, e
	}
	if e := s.Validate(now); e != nil {
		return status.RootResponse{}, e
	}
	// A current database failure or altered public authority never becomes good.
	if !bytes.Equal(registered, s.Intermediate.Raw) || s.Intermediate.CheckSignatureFrom(s.Root) != nil {
		return status.RootResponse{}, ErrIssuer
	}
	crlDER, e := s.CRL.ReadRootCRL(ctx)
	if e != nil {
		return status.RootResponse{}, e
	}
	list, e := x509.ParseRevocationList(crlDER)
	if e != nil {
		return status.RootResponse{}, e
	}
	if !list.Number.IsInt64() {
		return status.RootResponse{}, ErrIssuer
	}
	// An offline-revoked OCSP delegate cannot continue attesting any state.
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(s.Credential.SerialNumber) == 0 {
			return status.RootResponse{}, ErrIssuer
		}
	}
	serial, ok := new(big.Int).SetString(string(id.Serial), 16)
	if !ok || serial.Sign() <= 0 || serial.BitLen() > 159 {
		return status.RootResponse{}, ErrIssuer
	}
	state := ocsp.Unknown
	if serial.Cmp(s.Intermediate.SerialNumber) == 0 {
		state = ocsp.Good
	}
	tmpl := ocsp.Response{SerialNumber: serial, Status: state, ThisUpdate: now.UTC().Truncate(time.Second), NextUpdate: now.Add(5 * time.Minute).UTC().Truncate(time.Second), Certificate: s.Credential, IssuerHash: hashAlgorithm(id.Hash)}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(serial) == 0 {
			tmpl.Status = ocsp.Revoked
			tmpl.RevokedAt = entry.RevocationTime
			tmpl.RevocationReason = entry.ReasonCode
		}
	}
	for _, until := range []time.Time{list.NextUpdate, s.Credential.NotAfter, s.Root.NotAfter} {
		if tmpl.NextUpdate.After(until) {
			tmpl.NextUpdate = until
		}
	}
	if !tmpl.NextUpdate.After(now) {
		return status.RootResponse{}, ErrIssuer
	}
	der, e := ocsp.CreateResponse(s.Root, s.Credential, tmpl, s.key)
	if e != nil {
		return status.RootResponse{}, e
	}
	if _, e = ocsp.ParseResponse(der, s.Root); e != nil {
		return status.RootResponse{}, e
	}
	return status.RootResponse{DER: der, CRL: status.RootCRL{RevokedSerials: rootRevokedSerials(list), Issuer: certificateID(s.Root), Number: list.Number.Int64(), DER: crlDER}}, nil
}

func (s *RootStatus) RootList(ctx context.Context) (status.RootCRL, error) {
	der, e := s.CRL.ReadRootCRL(ctx)
	if e != nil {
		return status.RootCRL{}, e
	}
	list, e := x509.ParseRevocationList(der)
	if e != nil || !list.Number.IsInt64() {
		return status.RootCRL{}, ErrIssuer
	}
	return status.RootCRL{RevokedSerials: rootRevokedSerials(list), Issuer: certificateID(s.Root), Number: list.Number.Int64(), DER: der}, nil
}

func rootRevokedSerials(list *x509.RevocationList) []string {
	out := make([]string, 0, len(list.RevokedCertificateEntries))
	for _, entry := range list.RevokedCertificateEntries {
		out = append(out, entry.SerialNumber.String())
	}
	return out
}
