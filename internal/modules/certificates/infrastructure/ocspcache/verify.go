package ocspcache

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"gatebeam/internal/modules/certificates/application/statuscache"
	"golang.org/x/crypto/ocsp"
	"slices"
	"sync"
	"time"
)

type Request = statuscache.Request

var ErrUnsafe = statuscache.ErrUnsafe

const MaxDER = statuscache.MaxDER

type Verifier struct {
	mu      sync.Mutex
	issuers map[string]*x509.Certificate
}

func NewVerifier(issuers [][]byte) (*Verifier, error) {
	v := &Verifier{issuers: map[string]*x509.Certificate{}}
	if err := v.AddIssuers(issuers); err != nil {
		return nil, err
	}
	return v, nil
}
func (v *Verifier) AddIssuers(issuers [][]byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	next := make(map[string]*x509.Certificate, len(v.issuers))
	for fp, cert := range v.issuers {
		next[fp] = cert
	}
	for _, der := range issuers {
		issuer, err := x509.ParseCertificate(bytes.Clone(der))
		if err != nil || !issuer.IsCA || issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
			return ErrUnsafe
		}
		sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		next[hex.EncodeToString(sum[:])] = issuer
	}
	if len(next) > 128 {
		return ErrUnsafe
	}
	v.issuers = next
	return nil
}
func (v *Verifier) Issuers() [][]byte {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out [][]byte
	for _, cert := range v.issuers {
		out = append(out, bytes.Clone(cert.Raw))
	}
	return out
}
func (v *Verifier) Request(r Request) (statuscache.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	req, err := v.request(r)
	if err != nil {
		return statuscache.Identity{}, err
	}
	return statuscache.Identity{IssuerFingerprint: req.fp, CertKey: req.certKey, CacheKey: req.cacheKey}, nil
}
func (v *Verifier) Verify(r Request, der []byte, now time.Time) (statuscache.Verdict, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	req, err := v.request(r)
	if err != nil {
		return statuscache.Verdict{}, err
	}
	parsed, err := validate(req, der, now)
	if err != nil {
		return statuscache.Verdict{}, err
	}
	return statuscache.Verdict{Good: parsed.Status == ocsp.Good, Revoked: parsed.Status == ocsp.Revoked}, nil
}

type parsedRequest struct {
	issuer                *x509.Certificate
	fp, certKey, cacheKey string
	id                    certID
	nonce                 []byte
}

func (s *Verifier) request(r Request) (parsedRequest, error) {
	var out parsedRequest
	if len(r.DER) == 0 || len(r.DER) > 4096 {
		return out, ErrUnsafe
	}
	var wire wireRequest
	rest, err := asn1.Unmarshal(r.DER, &wire)
	if err != nil || len(rest) != 0 || wire.Data.Version != 0 || len(wire.Data.Requests) != 1 || len(wire.Signature.FullBytes) != 0 || len(wire.Data.Requestor.FullBytes) != 0 || len(wire.Data.Requests[0].Extensions) != 0 {
		return out, ErrUnsafe
	}
	request, err := ocsp.ParseRequest(r.DER)
	if err != nil || request.SerialNumber.Sign() <= 0 || request.SerialNumber.BitLen() > 159 || !request.HashAlgorithm.Available() {
		return out, ErrUnsafe
	}
	n, err := nonce(wire.Data.Extensions)
	if err != nil {
		return out, err
	}
	for fp, issuer := range s.issuers {
		if r.IssuerFingerprint != "" && r.IssuerFingerprint != fp {
			continue
		}
		expectedDER, err := ocsp.CreateRequest(&x509.Certificate{SerialNumber: request.SerialNumber}, issuer, &ocsp.RequestOptions{Hash: request.HashAlgorithm})
		if err != nil {
			continue
		}
		expected, err := ocsp.ParseRequest(expectedDER)
		if err != nil || !bytes.Equal(expected.IssuerNameHash, request.IssuerNameHash) || !bytes.Equal(expected.IssuerKeyHash, request.IssuerKeyHash) {
			continue
		}
		if out.issuer != nil {
			return parsedRequest{}, ErrUnsafe
		}
		out.issuer = issuer
		out.fp = fp
	}
	if out.issuer == nil {
		return out, ErrUnsafe
	}
	out.id = wire.Data.Requests[0].Cert
	out.nonce = n
	sum := sha256.Sum256(r.DER)
	out.cacheKey = hex.EncodeToString(sum[:])
	sum = sha256.Sum256([]byte(out.fp + "/" + request.SerialNumber.Text(16)))
	out.certKey = hex.EncodeToString(sum[:])
	return out, nil
}

func validate(req parsedRequest, der []byte, now time.Time) (*ocsp.Response, error) {
	if len(der) == 0 || len(der) > MaxDER || now.Before(req.issuer.NotBefore) || !now.Before(req.issuer.NotAfter) {
		return nil, ErrUnsafe
	}
	response, err := ocsp.ParseResponse(der, req.issuer)
	if err != nil {
		return nil, ErrUnsafe
	}
	var data responseData
	rest, err := asn1.Unmarshal(response.TBSResponseData, &data)
	if err != nil || len(rest) != 0 || data.Version != 0 || len(data.Responses) != 1 || !sameID(req.id, data.Responses[0].Cert) {
		return nil, ErrUnsafe
	}
	n, err := nonce(data.Extensions)
	if err != nil || !bytes.Equal(n, req.nonce) || len(data.Responses[0].Extensions) != 0 {
		return nil, ErrUnsafe
	}
	if response.ThisUpdate.IsZero() || response.NextUpdate.IsZero() || response.ProducedAt.IsZero() || response.ThisUpdate.After(now) || response.ProducedAt.After(now) || !now.Before(response.NextUpdate) || !response.ThisUpdate.Before(response.NextUpdate) || response.Status == ocsp.Unknown {
		return nil, ErrUnsafe
	}
	signer := response.Certificate
	if signer == nil {
		signer = req.issuer
	}
	if len(response.RawResponderName) > 0 {
		if !bytes.Equal(response.RawResponderName, signer.RawSubject) {
			return nil, ErrUnsafe
		}
	} else {
		var public struct {
			Algorithm pkix.AlgorithmIdentifier
			Key       asn1.BitString
		}
		rest, err := asn1.Unmarshal(signer.RawSubjectPublicKeyInfo, &public)
		if err != nil || len(rest) != 0 {
			return nil, ErrUnsafe
		}
		hash := sha1.Sum(public.Key.RightAlign())
		if !bytes.Equal(response.ResponderKeyHash, hash[:]) {
			return nil, ErrUnsafe
		}
	}
	if delegate := response.Certificate; delegate != nil && !bytes.Equal(delegate.Raw, req.issuer.Raw) {
		roots := x509.NewCertPool()
		roots.AddCert(req.issuer)
		if delegate.KeyUsage&x509.KeyUsageDigitalSignature == 0 || !slices.Contains(delegate.ExtKeyUsage, x509.ExtKeyUsageOCSPSigning) {
			return nil, ErrUnsafe
		}
		if _, err = delegate.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning}}); err != nil {
			return nil, ErrUnsafe
		}
	}
	return response, nil
}
