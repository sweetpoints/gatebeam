package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"testing"
)

type foreignScope struct{}

func (foreignScope) Context() context.Context { return context.Background() }
func TestRejectForeignScope(t *testing.T) {
	called := false
	e := Use(foreignScope{}, func(context.Context, pgx.Tx) error { called = true; return nil })
	if !errors.Is(e, ErrInvalidScope) || called {
		t.Fatalf("foreign scope accepted: %v", e)
	}
}
