//go:build integration

package postgres_test

import (
	"context"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	repo "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/testkit"
	"strings"
	"testing"
	"time"
)

func TestPostApplyEvidenceDoesNotPromoteUncommittedArtifact(t *testing.T) {
	db := testkit.Postgres(t)
	store := repo.NewRuntime(db, nil, nil)
	ctx := context.Background()
	report := edge.RouteVerification{ArtifactID: strings.Repeat("a", 64), Version: "candidate", Generation: "g", CheckedAt: time.Now(), NativeVerified: true, Routes: []edge.RouteResult{{SiteID: "site", Host: "shop.test", SNI: "shop.test", Outcome: "degraded", Reason: "tls_or_route_probe_failed"}}}
	if err := store.SaveRouteVerification(ctx, report); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CurrentRouteVerification(ctx); err == nil {
		t.Fatal("failed candidate evidence appeared as current verified runtime")
	}
	id := "00000000-0000-4000-8000-000000000001"
	if _, err := db.Exec(ctx, "INSERT INTO deployment_candidates(id,body,input_digest)VALUES($1,'{}',$2)", id, strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "INSERT INTO deployment_releases(id,state)VALUES($1,'succeeded')", id); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, "INSERT INTO deployment_runtime(id,release_id,artifact_id,version)VALUES(true,$1,$2,$3)", id, strings.Repeat("b", 64), id+"/current"); err != nil {
		t.Fatal(err)
	}
	current := edge.RouteVerification{ArtifactID: strings.Repeat("b", 64), Version: id, Generation: "current", CheckedAt: time.Now(), NativeVerified: true, BusinessVerified: true}
	if err := store.SaveRouteVerification(ctx, current); err != nil {
		t.Fatal(err)
	}
	report.CheckedAt = time.Now().Add(time.Second)
	if err := store.SaveRouteVerification(ctx, report); err != nil {
		t.Fatal(err)
	}
	got, err := store.CurrentRouteVerification(ctx)
	if err != nil || got.ArtifactID != current.ArtifactID || !got.BusinessVerified {
		t.Fatal("later stale evidence replaced current artifact", got, err)
	}
	var count int
	if err := db.QueryRow(ctx, "SELECT count(*) FROM deployment_route_verifications WHERE body->'routes'->0->>'outcome'='degraded'").Scan(&count); err != nil || count != 2 {
		t.Fatal("failure evidence lost", count, err)
	}
}
