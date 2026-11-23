package identity

import (
	"context"
	repo "gatebeam/internal/modules/identity/infrastructure/postgres"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5/pgxpool"
	"time"
)

// RewrapRoleSecrets is controlled owner maintenance, never an HTTP operation.
// It does not alter logical identities, auth versions or immutable resources.
func RewrapRoleSecrets(ctx context.Context, p *pgxpool.Pool, identityFile string, recipients []string) (count int, err error) {
	secret, e := secrets.NewRoleStore(identityFile, recipients)
	if e != nil {
		return 0, e
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = pg.NewRunner(p).Within(ctx, func(sc transaction.Scope) (e error) { count, e = repo.New().RewrapRoleWithin(sc, secret); return })
	if err != nil {
		return 0, err
	}
	return
}

// VerifyRoleSecrets proves this replica can read history without resealing it.
func VerifyRoleSecrets(ctx context.Context, p *pgxpool.Pool, identityFile string, recipients []string) (count int, err error) {
	secret, e := secrets.NewRoleStore(identityFile, recipients)
	if e != nil {
		return 0, e
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	err = pg.NewRunner(p).Within(ctx, func(sc transaction.Scope) (e error) { count, e = repo.New().VerifyRoleWithin(sc, secret); return })
	if err != nil {
		return 0, err
	}
	return
}
