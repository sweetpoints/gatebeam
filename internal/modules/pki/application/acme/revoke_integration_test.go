//go:build integration

package acme_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	management "gatebeam/internal/modules/pki/application"
	app "gatebeam/internal/modules/pki/application/acme"
	statusapp "gatebeam/internal/modules/pki/application/status"
	pkicrypto "gatebeam/internal/modules/pki/infrastructure/crypto"
	josecrypto "gatebeam/internal/modules/pki/infrastructure/jose"
	repo "gatebeam/internal/modules/pki/infrastructure/postgres"
	transport "gatebeam/internal/modules/pki/transport/acme"
	"gatebeam/internal/platform/postgres"
	"strings"
	"testing"
)

func TestStandardRevokeCertJWSAccountAndCertificateKey(t *testing.T) {
	for _, mode := range []string{"account", "certificate-key"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			_, binding := f.grant("server")
			accountKey := key(t)
			kid := f.register(accountKey, binding, "server")
			pub, e := (josecrypto.Crypto{}).PublicKey(public(t, accountKey))
			if e != nil {
				t.Fatal(e)
			}
			ref := app.AccountRef{Directory: "server", ID: strings.TrimPrefix(kid, f.server.URL+"/acme/server/account/"), Thumbprint: pub.Thumbprint}
			issuer := issuerForOrders(t)
			f.now = issuer.Certificate.NotBefore
			tx := postgres.NewRunner(f.db)
			r := repo.New()
			if e = management.NewRegistry(tx, r).Register(context.Background(), issuer.Metadata(), issuer.Certificate.Raw); e != nil {
				t.Fatal(e)
			}
			orders := app.NewOrders(tx, r, pkicrypto.Random{}, validationFunc(func(context.Context, string, string, string) error { return nil }), pkicrypto.OrderSigner{Issuer: issuer}, nil)
			leafKey := key(t)
			csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{"host.example"}}, leafKey)
			if e != nil {
				t.Fatal(e)
			}
			order := readyOrder(t, orders, ref)
			if _, e = orders.Finalize(context.Background(), ref, order.ID, csr); e != nil {
				t.Fatal(e)
			}
			cert, e := orders.Certificate(context.Background(), ref, order.ID)
			if e != nil {
				t.Fatal(e)
			}
			protocol, e := transport.NewProtocol(f.server.URL, f.service, f.nonces, josecrypto.Crypto{}, orders)
			if e != nil {
				t.Fatal(e)
			}
			protocol.SetRevocations(statusapp.New(tx, r, pkicrypto.NewStatusSigner(issuer), nil))
			f.server.Config.Handler = protocol
			signer := accountKey
			signerID := kid
			if mode == "certificate-key" {
				signer = leafKey
				signerID = ""
			}
			path := "/acme/server/revoke-cert"
			post := func(reason int) (int, []byte) {
				payload, _ := json.Marshal(map[string]any{"certificate": base64.RawURLEncoding.EncodeToString(cert.DER), "reason": reason})
				status, _, body := f.post(path, signed(t, signer, "ES256", f.server.URL+path, f.nonce(), signerID, payload))
				return status, body
			}
			if status, body := post(8); status != 400 || !strings.Contains(string(body), "badRevocationReason") {
				t.Fatal("reason mapping", status, string(body))
			}
			if status, body := post(1); status != 200 {
				t.Fatal("standard revoke rejected", status, string(body))
			}
			if status, body := post(1); status != 400 || !strings.Contains(string(body), "alreadyRevoked") {
				t.Fatal("repeat mapping", status, string(body))
			}
		})
	}
}
