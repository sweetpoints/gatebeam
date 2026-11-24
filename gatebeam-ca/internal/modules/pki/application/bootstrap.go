// Package application owns PKI use cases and capability-free contracts.
package application

import (
	"context"
	"errors"
	"gatebeam-ca/internal/modules/pki/domain"
	"gatebeam-ca/internal/platform/transaction"
	"strings"
)

var ErrBootstrap = errors.New("invalid PKI bootstrap configuration")

type BootstrapCommand struct{ RootDirectory, OnlineDirectory, RootName, IntermediateName, StatusOrigin string }

func Bootstrap(ctx context.Context, g OfflineGenerator, c BootstrapCommand) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if g == nil || c.RootDirectory == "" || c.OnlineDirectory == "" || strings.TrimSpace(c.RootName) == "" || strings.TrimSpace(c.IntermediateName) == "" || len(c.RootName) > 64 || len(c.IntermediateName) > 64 {
		return ErrBootstrap
	}
	return g.Generate(ctx, c)
}

// Registry persists an immutable public issuer before the CA begins serving.
// Management assembly does not receive this write capability.
type Registry struct {
	tx    transaction.Runner
	store IssuerStore
}

func NewRegistry(tx transaction.Runner, store IssuerStore) *Registry {
	return &Registry{tx: tx, store: store}
}
func (s *Registry) Register(ctx context.Context, i domain.Issuer, der []byte) error {
	if i.ID == "" || i.Fingerprint == "" || !i.NotAfter.After(i.NotBefore) || len(der) == 0 || len(der) > 65536 {
		return ErrBootstrap
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return s.store.Register(sc, i, der) })
}
