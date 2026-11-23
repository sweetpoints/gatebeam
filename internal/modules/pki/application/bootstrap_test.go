package application

import (
	"context"
	"errors"
	"gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/transaction"
	"testing"
	"time"
)

type generationFailure struct {
	err    error
	called bool
}

func (g *generationFailure) Generate(context.Context, BootstrapCommand) error {
	g.called = true
	return g.err
}
func TestBootstrapValidatesBeforeIOAndPropagatesFailure(t *testing.T) {
	failure := errors.New("owned fixture storage failure")
	g := &generationFailure{err: failure}
	if e := Bootstrap(context.Background(), g, BootstrapCommand{}); !errors.Is(e, ErrBootstrap) || g.called {
		t.Fatal("invalid ceremony attempted I/O")
	}
	if e := Bootstrap(context.Background(), g, BootstrapCommand{RootDirectory: "/offline", OnlineDirectory: "/online", RootName: "root", IntermediateName: "intermediate"}); !errors.Is(e, failure) {
		t.Fatal("storage failure swallowed", e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	g.called = false
	if e := Bootstrap(ctx, g, BootstrapCommand{}); !errors.Is(e, context.Canceled) || g.called {
		t.Fatal("cancelled ceremony attempted I/O")
	}
}

type scope struct{ ctx context.Context }

func (s scope) Context() context.Context { return s.ctx }

type runner struct{}

func (runner) Within(ctx context.Context, fn func(transaction.Scope) error) error {
	return fn(scope{ctx})
}

type failingStore struct {
	err    error
	called bool
}

func (s *failingStore) Register(transaction.Scope, domain.Issuer, []byte) error {
	s.called = true
	return s.err
}
func (s *failingStore) ReserveSerial(transaction.Scope, domain.IssuerID, domain.Serial) error {
	return s.err
}
func TestRegistryRejectsInvalidMetadataAndPropagatesTransactionFailure(t *testing.T) {
	failure := errors.New("owned transaction failure")
	store := &failingStore{err: failure}
	registry := NewRegistry(runner{}, store)
	if e := registry.Register(context.Background(), domain.Issuer{}, []byte("der")); !errors.Is(e, ErrBootstrap) || store.called {
		t.Fatal("invalid metadata reached persistence")
	}
	now := time.Now()
	if e := registry.Register(context.Background(), domain.Issuer{ID: "id", Fingerprint: "fingerprint", NotBefore: now, NotAfter: now.Add(time.Hour)}, []byte("der")); !errors.Is(e, failure) {
		t.Fatal("transaction failure swallowed", e)
	}
}
