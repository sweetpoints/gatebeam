package pkicrypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/secrets"
	"math/big"
	"net/url"
	"slices"
	"time"
)

type Issuer struct {
	Certificate  *x509.Certificate
	Chain        []*x509.Certificate
	Signer       crypto.Signer
	StatusOrigin string
}

func parseCertificate(b []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, ErrIssuer
	}
	c, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		return nil, ErrIssuer
	}
	return c, nil
}
func parseKey(b []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 || len(block.Headers) != 0 {
		return nil, ErrIssuer
	}
	k, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, ErrIssuer
	}
	s, ok := k.(crypto.Signer)
	if !ok || !validPublicKey(s.Public()) {
		return nil, ErrIssuer
	}
	return s, nil
}
func validPublicKey(k any) bool {
	switch k := k.(type) {
	case *ecdsa.PublicKey:
		return k.Curve != nil && (k.Curve.Params().Name == "P-256" || k.Curve.Params().Name == "P-384") && k.Curve.IsOnCurve(k.X, k.Y)
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048 && k.N.BitLen() <= 8192 && k.E >= 65537
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	}
	return false
}
func LoadIssuer(cfg Config) (Issuer, error) {
	b, e := readFile(cfg.CertificateFile, false)
	if e != nil {
		return Issuer{}, e
	}
	c, e := parseCertificate(b)
	if e != nil {
		return Issuer{}, e
	}
	b, e = readFile(cfg.RootFile, false)
	if e != nil {
		return Issuer{}, e
	}
	root, e := parseCertificate(b)
	if e != nil {
		return Issuer{}, e
	}
	if _, e = readFile(cfg.IdentityFile, true); e != nil {
		return Issuer{}, e
	}
	store, e := secrets.New(cfg.IdentityFile)
	if e != nil {
		return Issuer{}, ErrIssuer
	}
	b, e = readFile(cfg.SignerFile, true)
	if e != nil {
		return Issuer{}, e
	}
	plain, e := store.Open("pki-online-issuer", b)
	if e != nil {
		return Issuer{}, ErrIssuer
	}
	defer clear(plain)
	signer, e := parseKey(plain)
	if e != nil {
		return Issuer{}, e
	}
	issuer := Issuer{Certificate: c, Chain: []*x509.Certificate{root}, Signer: signer}
	if e = issuer.Validate(time.Now()); e != nil {
		return Issuer{}, e
	}
	return issuer, nil
}

// Validate requires a direct, constrained intermediate beneath the explicit offline
// trust anchor. Identical public keys also reject a root key rewrapped as an intermediate.
func (i Issuer) Validate(now time.Time) error {
	c := i.Certificate
	if c == nil || i.Signer == nil || len(i.Chain) != 1 || i.Chain[0] == nil {
		return ErrIssuer
	}
	root := i.Chain[0]
	for _, v := range []*x509.Certificate{c, root} {
		if !v.IsCA || !v.BasicConstraintsValid || v.KeyUsage&x509.KeyUsageCertSign == 0 || v.KeyUsage&x509.KeyUsageCRLSign == 0 || now.Before(v.NotBefore) || !now.Before(v.NotAfter) || len(v.UnhandledCriticalExtensions) > 0 || !validPublicKey(v.PublicKey) {
			return ErrIssuer
		}
	}
	if root.MaxPathLenZero || !bytes.Equal(root.RawIssuer, root.RawSubject) || c.NotAfter.After(root.NotAfter) {
		return ErrIssuer
	}
	if !c.MaxPathLenZero || c.MaxPathLen != 0 || bytes.Equal(c.RawSubjectPublicKeyInfo, root.RawSubjectPublicKeyInfo) || root.CheckSignatureFrom(root) != nil || c.CheckSignatureFrom(root) != nil {
		return ErrIssuer
	}
	pub, e := x509.MarshalPKIXPublicKey(i.Signer.Public())
	if e != nil || !bytes.Equal(pub, c.RawSubjectPublicKeyInfo) {
		return ErrIssuer
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	// The bootstrap issuer serves both separately authorized leaf purposes. A CA
	// restricted to an unrelated EKU (or only one purpose) cannot serve this assembly.
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, e = c.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); e != nil {
			return ErrIssuer
		}
	}
	return nil
}
func (i Issuer) Metadata() domain.Issuer {
	sum := sha256.Sum256(i.Certificate.Raw)
	id := hex.EncodeToString(sum[:])
	return domain.Issuer{ID: domain.IssuerID(id), Fingerprint: id, NotBefore: i.Certificate.NotBefore, NotAfter: i.Certificate.NotAfter}
}

// NewSerial generates at most 159 bits: RFC 5280's positive, <=20-octet INTEGER.
// Persistence must reserve it with a unique (issuer, serial) constraint before use.
func NewSerial() (*big.Int, error) {
	for range 8 {
		b := make([]byte, 20)
		if _, e := rand.Read(b); e != nil {
			return nil, e
		}
		b[0] &= 0x7f
		s := new(big.Int).SetBytes(b)
		if s.Sign() > 0 {
			return s, nil
		}
	}
	return nil, ErrIssuer
}

// SignCSR is an infrastructure primitive, never an enrollment endpoint. The caller
// must hold the authorized order transaction and reserve serial before signing.
func (i Issuer) SignCSR(der []byte, p domain.Policy, orderNames []string, serial *big.Int, now time.Time, lifetime time.Duration) ([]byte, error) {
	if e := i.Validate(now); e != nil {
		return nil, e
	}
	if len(der) == 0 || len(der) > 65536 || p.Authorize(orderNames) != nil || serial == nil || serial.Sign() <= 0 || serial.BitLen() > 159 || lifetime <= 0 || lifetime > 24*time.Hour {
		return nil, ErrCSR
	}
	csr, e := x509.ParseCertificateRequest(der)
	if e != nil || csr.CheckSignature() != nil || !validPublicKey(csr.PublicKey) || len(csr.IPAddresses) > 0 || len(csr.EmailAddresses) > 0 || len(csr.URIs) > 0 || p.Authorize(csr.DNSNames) != nil {
		return nil, ErrCSR
	}
	names := slices.Clone(csr.DNSNames)
	wanted := slices.Clone(orderNames)
	slices.Sort(names)
	slices.Sort(wanted)
	if !slices.Equal(names, wanted) {
		return nil, ErrCSR
	}
	// Only the standard SAN request is supported. Never copy requester-controlled
	// basic constraints, key usage, EKU, policies, or unknown critical extensions.
	for _, ext := range csr.Extensions {
		if !ext.Id.Equal([]int{2, 5, 29, 17}) {
			return nil, ErrCSR
		}
	}
	usage := x509.ExtKeyUsageServerAuth
	if p.Usage() == domain.ClientAuth {
		usage = x509.ExtKeyUsageClientAuth
	} else if p.Usage() != domain.ServerAuth {
		return nil, ErrCSR
	}
	until := now.Add(lifetime)
	if until.After(i.Certificate.NotAfter) {
		until = i.Certificate.NotAfter
	}
	// Bounded issuance policy absorbs ordinary clock skew at X.509's seconds
	// precision. It never weakens verification or extends the requested expiry,
	// and a future/expired issuer has already failed Validate(now).
	from := now.Add(-time.Minute)
	if from.Before(i.Certificate.NotBefore) {
		from = i.Certificate.NotBefore
	}
	tmpl := &x509.Certificate{SerialNumber: serial, DNSNames: names, NotBefore: from, NotAfter: until, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage}}
	if i.StatusOrigin != "" {
		u, e := url.Parse(i.StatusOrigin)
		if e != nil || u.Scheme != "http" || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, ErrIssuer
		}
		tmpl.OCSPServer = []string{i.StatusOrigin + "/ocsp"}
		tmpl.CRLDistributionPoints = []string{i.StatusOrigin + "/crl/" + string(i.Metadata().ID) + ".der"}
	}
	signed, e := x509.CreateCertificate(rand.Reader, tmpl, i.Certificate, csr.PublicKey, i.Signer)
	if e != nil {
		return nil, ErrCSR
	}
	leaf, e := x509.ParseCertificate(signed)
	if e != nil {
		return nil, ErrCSR
	}
	roots := x509.NewCertPool()
	roots.AddCert(i.Chain[0])
	intermediates := x509.NewCertPool()
	intermediates.AddCert(i.Certificate)
	// Verify the resulting path before releasing bytes: the loaded CA can impose
	// DNS name constraints and other restrictions beyond the order's allowlist.
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}}); e != nil {
		return nil, ErrCSR
	}
	return signed, nil
}
