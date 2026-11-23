package ingressaccess_test

import (
	"context"
	"errors"
	"gatebeam/internal/integration/ingressaccess"
	"gatebeam/internal/modules/identity/application/access"
	ingress "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/transaction"
	"testing"
)

type scope struct{}

func (scope) Context() context.Context { return context.Background() }

type catalogRepository struct {
	ingress.Repository
	lockError, graphError error
}

func (r catalogRepository) ReadLock(transaction.Scope) error { return r.lockError }
func (r catalogRepository) Graph(transaction.Scope) (ingress.Graph, error) {
	return ingress.Graph{}, r.graphError
}
func (r catalogRepository) SiteGroups(transaction.Scope, string) ([]string, error) {
	if r.graphError != nil {
		return nil, r.graphError
	}
	return nil, domain.ErrNotFound
}
func TestCatalogPreservesStorageFailuresAndHidesUnknownResources(t *testing.T) {
	broken := errors.New("storage unavailable")
	id := "11111111-1111-4111-8111-111111111111"
	for _, repository := range []catalogRepository{{lockError: broken}, {graphError: broken}, {}} {
		catalog := &ingressaccess.Catalog{Ingress: ingress.New(nil, repository, nil, nil, nil)}
		_, siteError := catalog.SiteGroupsWithin(scope{}, id)
		groupError := catalog.GroupExistsWithin(scope{}, id)
		expected := broken
		if repository.lockError == nil && repository.graphError == nil {
			expected = access.ErrDenied
		}
		if !errors.Is(siteError, expected) || !errors.Is(groupError, expected) {
			t.Fatalf("catalog errors site=%v group=%v; expected %v", siteError, groupError, expected)
		}
	}
}
