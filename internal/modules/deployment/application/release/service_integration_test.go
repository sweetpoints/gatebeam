//go:build integration

package release_test

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
)

func TestImmutableCandidateUsesRealTransaction(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	ids := credential.New()
	s := release.New(repo.New(), ids)
	siteID, _ := ids.NewID()
	var candidate release.Candidate
	err := tx.Within(context.Background(), func(sc transaction.Scope) error {
		var e error
		candidate, e = s.PrepareWithin(sc, release.PrepareInput{Snapshot: app.Snapshot{Version: "deployment/v1", Sites: []app.Site{{ID: siteID, Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"a.example.test"}}}}}, AffectedSiteIDs: []string{siteID}, SelectedSiteIDs: []string{siteID}, Expected: map[string]int64{"site:" + siteID: 1}})
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	if candidate.ID == "" || candidate.InputDigest == "" {
		t.Fatal("missing immutable identity")
	}
}
