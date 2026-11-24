package status

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"time"

	app "gatebeam/internal/modules/certificates/application"

	"golang.org/x/crypto/ocsp"
)

// LeafVerifier checks gateway material against operator-pinned CA certificates
// and responders. It has no CA database connection.
type LeafVerifier struct {
	client  *Client
	issuers []*x509.Certificate
	roots   *x509.CertPool
	chain   *x509.CertPool
}

func NewLeafVerifier(client *Client, bundle []byte) (*LeafVerifier, error) {
	issuers, err := parsePEM(bundle)
	if err != nil || client == nil || len(issuers) == 0 || len(issuers) > 20 {
		return nil, ErrStatus
	}
	v := &LeafVerifier{client: client, issuers: issuers, roots: x509.NewCertPool(), chain: x509.NewCertPool()}
	hasRoot := false
	for _, issuer := range issuers {
		if !issuer.IsCA {
			return nil, ErrStatus
		}
		if _, err := v.profile(issuer); err != nil {
			return nil, err
		}
		if issuer.CheckSignatureFrom(issuer) == nil && bytes.Equal(issuer.RawSubject, issuer.RawIssuer) {
			v.roots.AddCert(issuer)
			hasRoot = true
		} else {
			v.chain.AddCert(issuer)
		}
	}
	if !hasRoot {
		return nil, ErrStatus
	}
	return v, nil
}

func (v *LeafVerifier) profile(issuer *x509.Certificate) (bound, error) {
	fp := fingerprint(issuer)
	var selected bound
	for _, candidate := range v.client.profiles {
		if slices.Contains(candidate.profile.Fingerprints, fp) {
			if selected.client != nil && selected.digest != candidate.digest {
				return bound{}, ErrStatus
			}
			selected = candidate
		}
	}
	if selected.client == nil {
		return bound{}, ErrStatus
	}
	return selected, nil
}

func (v *LeafVerifier) Verify(ctx context.Context, cert app.StoredVersion, managed bool, now time.Time) error {
	certs, err := parsePEM(cert.CertificatePEM)
	if err != nil || len(certs) == 0 || certs[0].IsCA {
		return ErrStatus
	}
	leaf := certs[0]
	known := false
	for _, issuer := range v.issuers {
		sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		if cert.IssuerKeyFingerprint == hex.EncodeToString(sum[:]) || leaf.CheckSignatureFrom(issuer) == nil {
			known = true
			break
		}
	}
	if !managed && !known {
		return nil
	}
	if cert.Serial != fmt.Sprintf("%040x", leaf.SerialNumber) || cert.LeafFingerprint != fingerprint(leaf) {
		return ErrStatus
	}
	var usage x509.ExtKeyUsage
	switch cert.Purpose {
	case "serverAuth":
		usage = x509.ExtKeyUsageServerAuth
	case "clientAuth":
		usage = x509.ExtKeyUsageClientAuth
	default:
		return ErrStatus
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: v.chain, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
	if err != nil || len(chains) != 1 || len(chains[0]) < 2 {
		return ErrStatus
	}
	chain := chains[0]
	issuerKey := sha256.Sum256(chain[1].RawSubjectPublicKeyInfo)
	if cert.Issuer != fingerprint(chain[1]) || cert.IssuerKeyFingerprint != hex.EncodeToString(issuerKey[:]) {
		return ErrStatus
	}
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	started := time.Now()
	for index := 0; index+1 < len(chain); index++ {
		if err := v.verifyPair(ctx, chain[index], chain[index+1], now.Add(time.Since(started))); err != nil {
			return fmt.Errorf("verify certificate status at depth %d: %w", index, err)
		}
	}
	return nil
}

func (v *LeafVerifier) verifyPair(ctx context.Context, cert, issuer *x509.Certificate, now time.Time) error {
	p, err := v.profile(issuer)
	if err != nil {
		return err
	}
	fp := fingerprint(issuer)
	crlURL, ocspURL := p.profile.CRLURLs[fp], p.profile.OCSPURLs[fp]
	if !slices.Contains(cert.CRLDistributionPoints, crlURL) || !slices.Contains(cert.OCSPServer, ocspURL) {
		return fmt.Errorf("certificate responder URLs differ from policy: %w", ErrStatus)
	}
	started := time.Now()
	raw, err := fetch(ctx, p.client, crlURL, nil)
	now = now.Add(time.Since(started))
	if err != nil {
		return fmt.Errorf("read issuer CRL: %w", err)
	}
	list, err := x509.ParseRevocationList(raw)
	if err != nil || list.CheckSignatureFrom(issuer) != nil || !bytes.Equal(list.RawIssuer, issuer.RawSubject) ||
		!bytes.Equal(list.AuthorityKeyId, issuer.SubjectKeyId) || now.Before(list.ThisUpdate) || !now.Before(list.NextUpdate) {
		return fmt.Errorf("verify issuer CRL: %w", ErrStatus)
	}
	for _, ext := range list.Extensions {
		// Only complete issuer-wide CRLs are accepted here.
		if ext.Critical || ext.Id.String() == "2.5.29.27" || ext.Id.String() == "2.5.29.28" {
			return ErrStatus
		}
	}
	for _, entry := range list.RevokedCertificateEntries {
		if entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return fmt.Errorf("certificate is revoked by issuer CRL: %w", ErrStatus)
		}
	}
	if _, err := checkOCSP(ctx, p.client, ocspURL, cert, issuer, ocsp.Good, now); err != nil {
		return fmt.Errorf("verify OCSP response: %w", err)
	}
	return nil
}
