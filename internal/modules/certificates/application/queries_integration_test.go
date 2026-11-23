//go:build integration

package application_test

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"testing"
)

type activeRevisionOne struct{}

func (activeRevisionOne) ForSpecWithin(transaction.Scope, string) ([]app.ActiveBinding, error) {
	return []app.ActiveBinding{{SpecRevision: 1, VersionID: "owned-active-version"}}, nil
}
func TestQueriesKeepActiveRevisionFailureSeparateFromNewManagementRevision(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(p)
	guard := security{tx}
	repo := certpg.New()
	crypto := certcrypto.Crypto{}
	management := app.NewManagement(guard, guard, repo, crypto, secret{}, secret{}, audit.New())
	account, e := management.SaveAccount(ctx, app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	config := app.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"}
	spec, e := management.SaveSpec(ctx, app.ActorRef{}, "", 0, config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = management.SaveSpec(ctx, app.ActorRef{}, spec.ID, 1, config); e != nil {
		t.Fatal(e)
	}
	apiOnly := app.New(tx, repo, guard, crypto, nil, nil, nil, management)
	if _, e = apiOnly.RenewRevision(ctx, spec.ID, 1); !errors.Is(e, app.ErrDenied) {
		t.Fatal("management assembly gained historical issuance capability", e)
	}
	worker := app.New(tx, repo, guard, crypto, secret{}, &failingCA{}, jobs.New(p))
	if _, e = worker.EnsureRevision(ctx, spec.ID, 1); e == nil {
		t.Fatal("old published issuance failure missing")
	}

	var fingerprint, state string
	if e = p.QueryRow(ctx, `SELECT payload->>'fingerprint',payload->>'state' FROM outbox WHERE event_type='CertificateRenewalChanged' AND aggregate_id=$1`, spec.ID).Scan(&fingerprint, &state); e != nil || fingerprint != "1" || state != "firing" {
		t.Fatal("published historical revision notification missing", fingerprint, state, e)
	}
	queries := app.NewQueries(guard, guard, certpg.NewPublicReader(), activeRevisionOne{})
	result, e := queries.Read(ctx, app.ActorRef{}, "spec", spec.ID)
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(result)
	var view struct {
		Revision  int64 `json:"revision"`
		Lifecycle struct {
			Failures  int `json:"failures"`
			Revisions []struct {
				Revision    int64   `json:"revision"`
				Failures    int     `json:"failures"`
				NextAttempt *string `json:"next_attempt"`
			} `json:"revisions"`
		} `json:"lifecycle"`
	}
	if e = json.Unmarshal(raw, &view); e != nil {
		t.Fatal(e)
	}
	if view.Revision != 2 || view.Lifecycle.Failures != 0 {
		t.Fatal("old failure assigned to new management revision")
	}
	found := false
	for _, r := range view.Lifecycle.Revisions {
		if r.Revision == 1 {
			found = r.Failures == 1 && r.NextAttempt != nil
		}
		if r.Revision == 2 && r.Failures != 0 {
			t.Fatal("management revision inherited old failure")
		}
	}
	if !found {
		t.Fatal("active revision1 renewal failure/backoff hidden by current revision2")
	}
}
