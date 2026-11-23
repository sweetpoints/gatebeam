//go:build integration

package postgres_test

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"strings"
	"testing"
)

func TestVerifiedMaterialBindingsShareFinalReceiptTransaction(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := postgres.NewRunner(p)
	store := repo.New()
	owner := release.New(store, identifiers.Generator{})
	id := "00000000-0000-4000-8000-000000000001"
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		if e := store.Save(sc, release.Candidate{ID: id, InputDigest: strings.Repeat("a", 64), Snapshot: app.Snapshot{Version: id}}); e != nil {
			return e
		}
		_, _, e := store.Queue(sc, id)
		return e
	}); e != nil {
		t.Fatal(e)
	}
	read := func() release.VerifiedBindings {
		var out release.VerifiedBindings
		if e := tx.Within(ctx, func(sc transaction.Scope) error {
			var e error
			out, e = owner.CurrentMaterialBindingsWithin(sc)
			return e
		}); e != nil {
			t.Fatal(e)
		}
		return out
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return owner.RecordVerifiedWithin(sc, id, strings.Repeat("a", 64), id+"/g1")
	}); e != nil {
		t.Fatal(e)
	}
	if out := read(); len(out.Materials) != 0 {
		t.Fatal("legacy receipt inferred bindings", out)
	}
	first := []release.MaterialBinding{{Kind: "certificate", ID: "owned-spec", Revision: 1, VersionID: "version-1", Digest: strings.Repeat("b", 64)}}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return owner.RecordVerifiedMaterialsWithin(sc, id, strings.Repeat("b", 64), id+"/g2", first)
	}); e != nil {
		t.Fatal(e)
	}
	before := read()
	if len(before.Materials) != 1 || before.Materials[0].VersionID != "version-1" || before.Generation != "g2" || before.VerifiedAt.IsZero() {
		t.Fatal("exact verified binding missing", before)
	}
	sentinel := errors.New("owned final transaction failure")
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		if e := owner.RecordVerifiedMaterialsWithin(sc, id, strings.Repeat("c", 64), id+"/g3", []release.MaterialBinding{{Kind: "certificate", ID: "owned-spec", Revision: 2, VersionID: "version-2"}}); e != nil {
			return e
		}
		return sentinel
	}); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	after := read()
	if after.ArtifactID != before.ArtifactID || after.Materials[0].VersionID != "version-1" || !after.VerifiedAt.Equal(before.VerifiedAt) {
		t.Fatal("failed final transaction changed binding", after)
	}
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		return owner.RecordVerifiedMaterialsWithin(sc, id, strings.Repeat("d", 64), id+"/g4", nil)
	}); e != nil {
		t.Fatal(e)
	}
	if out := read(); len(out.Materials) != 0 || out.ArtifactID != strings.Repeat("d", 64) {
		t.Fatal("old binding survived a new current artifact", out)
	}
}
