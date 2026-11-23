package certificates

import (
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/httpchallenge"
	acmeclient "gatebeam/internal/modules/certificates/infrastructure/lego"
	"github.com/google/uuid"
	"net/http"
	"sync"
	"time"
)

// PrivateTLSRequest belongs to one running role. The existing private key and
// manually authorized standard EAB credentials never cross role boundaries.
type PrivateHTTPChallenges = acmeclient.HTTPChallenges

type PrivateTLSRequest struct {
	Origin, Email, KeyID, HMAC, Purpose string
	Names                               []string
	PrivateKey, TransportTrust          []byte
}
type privateTLSCredentials struct {
	label string
	raw   []byte
}

func (c privateTLSCredentials) Open(label string, _ []byte) ([]byte, error) {
	if label != c.label {
		return nil, errors.New("private credential label denied")
	}
	return bytes.Clone(c.raw), nil
}
func (c privateTLSCredentials) Seal(string, []byte) ([]byte, error) {
	return nil, errors.New("private credential sealing denied")
}

type PrivateTLSFailure struct {
	Stage string
	Cause error
}

func (e PrivateTLSFailure) Error() string { return "private TLS " + e.Stage + " unavailable" }
func (e PrivateTLSFailure) Unwrap() error { return e.Cause }
func ObtainPrivateTLS(ctx context.Context, r PrivateTLSRequest, challenges acmeclient.HTTPChallenges) (out []byte, err error) {
	stage := "input"
	defer func() {
		if err != nil {
			err = PrivateTLSFailure{Stage: stage, Cause: err}
		}
	}()

	block, _ := pem.Decode(r.PrivateKey)
	if block == nil || block.Type != "PRIVATE KEY" || challenges == nil {
		return nil, acmeclient.ErrACME
	}
	key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return nil, e
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, acmeclient.ErrACME
	}
	provider := "internal-server"
	usage := x509.ExtKeyUsageServerAuth
	if r.Purpose == "clientAuth" {
		provider = "internal-client"
		usage = x509.ExtKeyUsageClientAuth
	} else if r.Purpose != "serverAuth" {
		return nil, acmeclient.ErrACME
	}
	id := uuid.NewString()
	spec, _ := json.Marshal(app.Spec{Names: r.Names, Purpose: r.Purpose, Method: "acme", ProviderID: id, Challenge: "http-01", TrustID: uuid.NewSHA1(uuid.NameSpaceOID, r.TransportTrust).String(), TrustRevision: 1})
	account, _ := json.Marshal(app.ProviderAccount{Provider: provider, Email: r.Email, EABKeyID: r.KeyID})
	plain, _ := json.Marshal(struct{ Key, EAB []byte }{r.PrivateKey, []byte(r.HMAC)})
	defer clear(plain)
	labelBody, _ := json.Marshal([]any{"account", id, int64(1)})
	credentials := privateTLSCredentials{label: "certificates/" + string(labelBody), raw: plain}
	hc := acmeclient.HTTPClient()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(r.TransportTrust) {
		return nil, acmeclient.ErrACME
	}
	transport := hc.Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
	hc.Transport = transport
	client := &acmeclient.Client{Secrets: credentials, HTTPChallenges: challenges, InternalOrigin: r.Origin, InternalHTTPClient: hc, PrivateKey: signer}
	stage = "acme"
	issued, e := client.Obtain(ctx, app.Work{Spec: app.Record{Resource: app.Resource{ID: uuid.NewString(), Kind: "spec", Revision: 1, Body: spec}}, Account: app.Record{Resource: app.Resource{ID: id, Kind: "account", Revision: 1, Body: account}}, Token: uuid.NewString()})
	if e != nil {
		return nil, e
	}
	defer clear(issued.KeyPEM)
	stage = "issued-key"
	pair, e := tls.X509KeyPair(issued.CertificatePEM, r.PrivateKey)
	if e != nil || len(pair.Certificate) == 0 {
		return nil, acmeclient.ErrACME
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.IsCA || len(leaf.DNSNames) != len(r.Names) {
		return nil, acmeclient.ErrACME
	}
	intermediates := x509.NewCertPool()
	for _, raw := range pair.Certificate[1:] {
		c, e := x509.ParseCertificate(raw)
		if e != nil {
			return nil, e
		}
		intermediates.AddCert(c)
	}
	stage = "issued-chain"
	for _, name := range r.Names {
		if leaf.VerifyHostname(name) != nil {
			return nil, acmeclient.ErrACME
		}
	}
	if _, e = leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{usage}}); e != nil {
		return nil, e
	}
	return issued.CertificatePEM, nil
}

// PrivateLocalHTTPChallenges publishes only on the owning node's private DNS
// endpoint. It has no database or peer publication capability.
type PrivateLocalHTTPChallenges struct {
	mu      sync.Mutex
	files   *httpchallenge.Files
	pending map[string]app.HTTPChallenge
}

func NewPrivateLocalHTTPChallenges(ctx context.Context, root string) (*PrivateLocalHTTPChallenges, error) {
	f, e := httpchallenge.NewScoped(root, ".gatebeam-http01-private-role")
	if e != nil {
		return nil, e
	}
	if e = f.Reconcile(ctx, nil); e != nil {
		return nil, e
	}
	return &PrivateLocalHTTPChallenges{files: f, pending: map[string]app.HTTPChallenge{}}, nil
}
func (c *PrivateLocalHTTPChallenges) PrepareCurrent(ctx context.Context, owner, token, key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pending[token] = app.HTTPChallenge{Owner: owner, Token: token, KeyAuthorization: key}
	return c.reconcile(ctx)
}
func (c *PrivateLocalHTTPChallenges) reconcile(ctx context.Context) error {
	pending := make([]app.HTTPChallenge, 0, len(c.pending))
	for _, v := range c.pending {
		pending = append(pending, v)
	}
	return c.files.Reconcile(ctx, pending)
}
func (c *PrivateLocalHTTPChallenges) Ready(context.Context, string) (bool, error) { return true, nil }
func (c *PrivateLocalHTTPChallenges) Cleanup(ctx context.Context, owner string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.pending {
		if v.Owner == owner {
			delete(c.pending, k)
		}
	}
	return c.reconcile(ctx)
}
