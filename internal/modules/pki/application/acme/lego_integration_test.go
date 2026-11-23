//go:build integration

package acme_test

import (
	"context"
	"crypto"
	legoacme "github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/acme/api"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/registration"
	"io"
	"log/slog"
	"testing"
	"time"
)

type legoUser struct {
	key     crypto.Signer
	account *legoacme.ExtendedAccount
}

func (u *legoUser) GetEmail() string                           { return "" }
func (u *legoUser) GetRegistration() *legoacme.ExtendedAccount { return u.account }
func (u *legoUser) GetPrivateKey() crypto.Signer               { return u.key }
func TestUnmodifiedLegoRegistrationRecoveryAndRollover(t *testing.T) {
	previous := legolog.Default()
	legolog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	t.Cleanup(func() { legolog.SetDefault(previous) })
	f := newFixture(t)
	_, binding := f.grant("server")
	u := &legoUser{key: key(t)}
	core, e := api.New(f.server.Client(), "Gatebeam-owned-test", f.server.URL+"/acme/server/directory", "", u.key)
	if e != nil {
		t.Fatal("lego directory", e)
	}
	registrar := registration.NewRegistrar(core, u)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	u.account, e = registrar.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{Kid: binding.KeyID, HmacEncoded: binding.HMAC, TermsOfServiceAgreed: true})
	if e != nil {
		t.Fatal("lego registration", e)
	}
	if _, e = registrar.QueryRegistration(ctx); e != nil {
		t.Fatal("lego POST-as-GET", e)
	}
	f.now = f.now.Add(16 * time.Minute)
	f.restart()
	core, e = api.New(f.server.Client(), "Gatebeam-owned-test", f.server.URL+"/acme/server/directory", "", u.key)
	if e != nil {
		t.Fatal(e)
	}
	registrar = registration.NewRegistrar(core, u)
	recovered, e := registrar.ResolveAccountByKey(ctx)
	if e != nil || recovered.Location != u.account.Location {
		t.Fatal("lego account recovery", e)
	}
	next := key(t)
	if e = registrar.KeyRollover(ctx, next); e != nil {
		t.Fatal("lego rollover", e)
	}
	u.key = next
	if _, e = registrar.QueryRegistration(ctx); e != nil {
		t.Fatal("lego post-rollover account", e)
	}
}
