// Package lego uses the unmodified standard ACME v2 client with one fixed issuer.
package lego

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/infrastructure/cloudflare"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/providers/http/webroot"
	"github.com/go-acme/lego/v5/registration"
	"net"
	"net/http"
	"net/url"
	"time"
)

var ErrACME = errors.New("configured ACME issuer operation failed")

type Client struct {
	PrivateKey         crypto.Signer
	HTTPChallenges     HTTPChallenges
	Journal            app.ChallengeJournal
	Secrets            app.Secrets
	WebRoot            string
	HTTPClient         *http.Client
	InternalHTTPClient *http.Client
	Directories        map[string]string
	InternalOrigin     string
	DNSBase            string
}
type user struct {
	email   string
	key     crypto.Signer
	account *acme.ExtendedAccount
}

func (u *user) GetEmail() string                       { return u.email }
func (u *user) GetRegistration() *acme.ExtendedAccount { return u.account }
func (u *user) GetPrivateKey() crypto.Signer           { return u.key }
func secretLabel(r app.Record) string {
	b, _ := json.Marshal([]any{r.Kind, r.ID, r.Revision})
	return "certificates/" + string(b)
}
func HTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func (c *Client) Obtain(ctx context.Context, w app.Work) (app.Issuance, error) {
	var spec app.Spec
	var account app.ProviderAccount
	if json.Unmarshal(w.Spec.Body, &spec) != nil || json.Unmarshal(w.Account.Body, &account) != nil || spec.Validate() != nil || account.Validate() != nil || app.ValidateEnrollment(spec, w.Account) != nil {
		return app.Issuance{}, ErrACME
	}
	directories := map[string]string{"letsencrypt": lego.DirectoryURLLetsEncrypt, "zerossl": lego.DirectoryURLZeroSSL, "google": lego.DirectoryURLGoogleTrust}
	// Overrides are constructor-only trusted lab/operator configuration, never a
	// provider-account request field. Production module supplies no overrides.
	if c.Directories != nil {
		directories = c.Directories
	}
	if account.Provider == "internal-client" || account.Provider == "internal-server" {
		origin, err := url.Parse(c.InternalOrigin)
		if err != nil || origin.Scheme != "https" || origin.Host == "" || origin.User != nil || origin.Path != "" || origin.RawQuery != "" || origin.Fragment != "" {
			return app.Issuance{}, ErrACME
		}
		directories = map[string]string{"internal-client": c.InternalOrigin + "/acme/client/directory", "internal-server": c.InternalOrigin + "/acme/server/directory"}
	}
	directory, ok := directories[account.Provider]
	if !ok {
		return app.Issuance{}, ErrACME
	}
	plain, e := c.Secrets.Open(secretLabel(w.Account), w.Account.Secret)
	if e != nil {
		return app.Issuance{}, ErrACME
	}
	defer clear(plain)
	var credentials struct{ Key, EAB []byte }
	if json.Unmarshal(plain, &credentials) != nil {
		return app.Issuance{}, ErrACME
	}
	defer clear(credentials.Key)
	defer clear(credentials.EAB)
	block, _ := pem.Decode(credentials.Key)
	if block == nil {
		return app.Issuance{}, ErrACME
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	if e != nil {
		return app.Issuance{}, ErrACME
	}
	key, ok := parsed.(crypto.Signer)
	if !ok {
		return app.Issuance{}, ErrACME
	}
	u := &user{email: account.Email, key: key}
	hc := c.HTTPClient
	if (account.Provider == "internal-client" || account.Provider == "internal-server") && c.InternalHTTPClient != nil {
		hc = c.InternalHTTPClient
	}
	if hc == nil {
		hc = HTTPClient()
	}
	cfg := &lego.Config{CADirURL: directory, User: u, HTTPClient: hc, Certificate: lego.CertificateConfig{Timeout: 45 * time.Second, OverallRequestLimit: 100}}
	client, e := lego.NewClient(cfg)
	if e != nil {
		return app.Issuance{}, ErrACME
	}
	var provider challenge.Provider
	switch spec.Challenge {
	case "http-01":
		if c.HTTPChallenges != nil {
			provider = coordinatedHTTP{ctx: ctx, owner: w.Token, coordinator: c.HTTPChallenges}
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				_ = c.HTTPChallenges.Cleanup(cleanup, w.Token)
			}()
		} else {
			provider, e = webroot.NewHTTPProvider(c.WebRoot)
		}
		if e == nil {
			e = client.Challenge.SetHTTP01Provider(provider)
		}
	case "dns-01":
		zones := []cloudflare.Zone{}
		for _, r := range w.Credentials {
			var zone app.DNSCredential
			if json.Unmarshal(r.Body, &zone) != nil || zone.Validate() != nil {
				return app.Issuance{}, ErrACME
			}
			token, err := c.Secrets.Open(secretLabel(r), r.Secret)
			if err != nil {
				return app.Issuance{}, ErrACME
			}
			defer clear(token)
			zones = append(zones, cloudflare.Zone{ID: zone.ZoneID, Name: zone.ZoneName, Token: token, CredentialID: r.ID, CredentialRevision: r.Revision})
		}
		base := c.DNSBase
		if base == "" {
			base = "https://api.cloudflare.com/client/v4"
		}
		provider, e = cloudflare.NewDNS(base, hc, zones, w.Token, c.Journal)
		if e == nil {
			e = client.Challenge.SetDNS01Provider(provider)
		}
	default:
		return app.Issuance{}, ErrACME
	}
	if e != nil {
		return app.Issuance{}, ErrACME
	}
	if account.EABKeyID != "" {
		u.account, e = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{TermsOfServiceAgreed: true, Kid: account.EABKeyID, HmacEncoded: string(credentials.EAB)})
	} else {
		u.account, e = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	}
	if e != nil {
		return app.Issuance{}, ErrACME
	}
	v, e := client.Certificate.Obtain(ctx, certificate.ObtainRequest{PrivateKey: c.PrivateKey, Domains: spec.Names, KeyType: certcrypto.EC256, Bundle: true})
	if e != nil {
		return app.Issuance{}, ErrACME
	}
	return app.Issuance{CertificatePEM: v.Certificate, KeyPEM: v.PrivateKey}, nil
}

func (c *Client) Cleanup(ctx context.Context) error {
	if c.Journal == nil {
		return nil
	}
	pending, e := c.Journal.Pending(ctx)
	if e != nil {
		return e
	}
	for _, v := range pending {
		var credential app.DNSCredential
		if json.Unmarshal(v.Credential.Body, &credential) != nil {
			return ErrACME
		}
		token, e := c.Secrets.Open(secretLabel(v.Credential), v.Credential.Secret)
		if e != nil {
			return ErrACME
		}
		base := c.DNSBase
		if base == "" {
			base = "https://api.cloudflare.com/client/v4"
		}
		hc := c.HTTPClient
		if hc == nil {
			hc = HTTPClient()
		}
		dns, e := cloudflare.NewDNS(base, hc, []cloudflare.Zone{{ID: credential.ZoneID, Name: credential.ZoneName, Token: token, CredentialID: v.Credential.ID, CredentialRevision: v.Credential.Revision}}, v.Receipt.Owner, c.Journal)
		if e == nil {
			e = dns.Recover(ctx, v.Receipt)
		}
		clear(token)
		if e != nil {
			return e
		}
	}
	return nil
}
