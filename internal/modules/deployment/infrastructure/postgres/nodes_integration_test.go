//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"fmt"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/identifiers"
	dep "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"strings"
	"testing"
	"time"
)

func TestReleaseWaitsForBothNodes(t *testing.T) {
	p := testkit.Postgres(t)
	owner := nodes.New(dep.New(), time.Now)
	owner.SetAudit(audit.New(), identifiers.Generator{})
	ids := []domain.NodeRef{{ID: "11111111-1111-4111-8111-111111111111", Epoch: 1}, {ID: "22222222-2222-4222-8222-222222222222", Epoch: 1}}
	image := "sha256:" + strings.Repeat("a", 64)
	images := map[string]string{}
	protocols := map[string]uint32{}
	for _, role := range []string{"nginx", "management", "background-jobs", "log-query"} {
		images[role] = image
		protocols[role] = 1
	}
	var schema string
	if err := p.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	var peers []*pgxpool.Pool
	for i, ref := range ids {
		principal := fmt.Sprintf("%s_node_%d", schema, i)
		quoted := pgx.Identifier{principal}.Sanitize()
		if _, err := p.Exec(t.Context(), `CREATE ROLE `+quoted+` LOGIN PASSWORD 'fixture-only';GRANT USAGE ON SCHEMA `+pgx.Identifier{schema}.Sanitize()+` TO `+quoted+`;GRANT SELECT ON deployment_nodes,deployment_desired,deployment_node_runtime,deployment_node_events,deployment_candidates,deployment_releases,deployment_runtime,deployment_generation TO `+quoted+`;GRANT UPDATE(id) ON deployment_generation TO `+quoted+`;GRANT INSERT,UPDATE ON deployment_node_runtime,deployment_node_events TO `+quoted); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP OWNED BY `+quoted+`;DROP ROLE `+quoted) })
		spec := nodes.NodeRegistration{Node: ref, Principal: principal, RuntimeProtocol: 1, BootFormat: 1, BootArtifactID: strings.Repeat("b", 64), BridgeImages: images, RoleProtocols: protocols}
		if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error { _, err := owner.RegisterWithin(sc, spec); return err }); err != nil {
			t.Fatal(err)
		}
		cfg := p.Config().Copy()
		cfg.MaxConns = 1
		cfg.ConnConfig.User = principal
		cfg.ConnConfig.Password = "fixture-only"
		peer, err := pgxpool.NewWithConfig(t.Context(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(peer.Close)
		peers = append(peers, peer)
	}
	releaseID := uuid.NewString()
	if _, err := p.Exec(t.Context(), `WITH candidate AS (INSERT INTO deployment_candidates(id,body,input_digest) VALUES($1,'{}',repeat('a',64)) RETURNING id) INSERT INTO deployment_releases(id) SELECT id FROM candidate`, releaseID); err != nil {
		t.Fatal(err)
	}
	if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		if err := owner.ActivateWithin(sc, ids); err != nil {
			return err
		}
		_, err := owner.SetDesiredWithin(sc, releaseID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM audit WHERE action IN('deployment.node.registered','deployment.nodes.activated')`).Scan(&auditCount); err != nil || auditCount != 3 {
		t.Fatalf("node administrator command journal incomplete: %d %v", auditCount, err)
	}
	now := time.Now().UTC()
	observation := nodes.Observation{EventID: uuid.NewString(), Node: ids[0], ReleaseID: releaseID, ArtifactID: strings.Repeat("c", 64), Generation: "g1", ImageDigest: image, ObservedAt: now, State: "succeeded"}
	report := func(peer int, value nodes.Observation) error {
		return postgres.NewRunner(peers[peer]).Within(t.Context(), func(sc transaction.Scope) error { return owner.ReportWithin(sc, value) })
	}
	if err := report(0, observation); err != nil {
		t.Fatal(err)
	}
	if err := report(0, observation); err != nil {
		t.Fatalf("duplicate event is not idempotent: %v", err)
	}
	summary := func() nodes.Summary {
		t.Helper()
		var out nodes.Summary
		err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
			var err error
			out, err = owner.SummaryWithin(sc, releaseID)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	altered := observation
	altered.ArtifactID = strings.Repeat("d", 64)
	if err := report(0, altered); err == nil {
		t.Fatal("duplicate event changed its immutable fact")
	}
	wrongImage := observation
	wrongImage.EventID = uuid.NewString()
	wrongImage.ImageDigest = "sha256:" + strings.Repeat("f", 64)
	if err := report(0, wrongImage); err == nil {
		t.Fatal("unapproved runtime image reported success")
	}
	// Bind DB row writes too: changing search_path cannot grant the runtime
	// login registrar privileges through an attacker-owned temporary table.
	connection, err := peers[0].Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = connection.Exec(t.Context(), `CREATE TEMP TABLE deployment_nodes(id int)`); err != nil {
		connection.Release()
		t.Fatal(err)
	}
	if _, err = connection.Exec(t.Context(), `SET search_path=pg_temp,`+pgx.Identifier{schema}.Sanitize()); err != nil {
		connection.Release()
		t.Fatal(err)
	}
	forgedObservation := observation
	forgedObservation.Node = ids[1]
	forgedObservation.EventID = uuid.NewString()
	forgedBody, _ := json.Marshal(forgedObservation)
	_, forgeryErr := connection.Exec(t.Context(), `INSERT INTO `+pgx.Identifier{schema, "deployment_node_events"}.Sanitize()+`(node_id,node_epoch,release_id,event_id,body,observed_at) VALUES($1,$2,$3,$4,$5,clock_timestamp())`, ids[1].ID, int64(ids[1].Epoch), releaseID, forgedObservation.EventID, forgedBody)
	_, restoreErr := connection.Exec(t.Context(), `SET search_path=`+pgx.Identifier{schema}.Sanitize())
	_, dropErr := connection.Exec(t.Context(), `DROP TABLE pg_temp.deployment_nodes`)
	connection.Release()
	if forgeryErr == nil || restoreErr != nil || dropErr != nil {
		t.Fatalf("database principal binding bypass: forge=%v restore=%v cleanup=%v", forgeryErr, restoreErr, dropErr)
	}
	if got := summary(); got.Complete || got.State != "partial_success" || got.Expected != 2 || got.Succeeded != 1 {
		t.Fatalf("one node became global success: %+v", got)
	}
	failed := observation
	failed.Node = ids[1]
	failed.EventID = uuid.NewString()
	failed.State = "failed"
	failed.ArtifactID = ""
	failed.Generation = ""
	if err := report(1, failed); err != nil {
		t.Fatal(err)
	}
	if got := summary(); got.Complete || got.State != "partial_success" {
		t.Fatalf("mixed result collapsed to complete: %+v", got)
	}
	forged := observation
	forged.Node = ids[1]
	forged.EventID = uuid.NewString()
	if err := report(0, forged); err == nil {
		t.Fatal("connection principal forged another node")
	}
	old := observation
	old.Node.Epoch = 2
	old.EventID = uuid.NewString()
	if err := report(0, old); err == nil {
		t.Fatal("wrong incarnation accepted")
	}
	if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error { return owner.ReportWithin(sc, observation) }); err == nil {
		t.Fatal("administrator connection impersonated data-plane observation")
	}
	success := observation
	success.Node = ids[1]
	success.EventID = uuid.NewString()
	success.ObservedAt = now.Add(time.Millisecond)
	if err := report(1, success); err != nil {
		t.Fatal(err)
	}
	if got := summary(); !got.Complete || got.State != "succeeded" {
		t.Fatalf("two verified nodes did not complete: %+v", got)
	}
	if err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error { return owner.SetStatusWithin(sc, ids[1], "revoked") }); err != nil {
		t.Fatal(err)
	}
	if got := summary(); got.Complete || !got.Degraded {
		t.Fatalf("revoked node still counted as fully serving: %+v", got)
	}
	success.EventID = uuid.NewString()
	if err := report(1, success); err == nil {
		t.Fatal("revoked node regained control privileges")
	}
}

func TestNodeIdentityLegacyOriginCannotBeCopiedToSecondNode(t *testing.T) {
	p := testkit.Postgres(t)
	owner := nodes.New(dep.New(), time.Now)
	releaseID := uuid.NewString()
	artifact := strings.Repeat("c", 64)
	image := "sha256:" + strings.Repeat("a", 64)
	if _, err := p.Exec(t.Context(), `WITH candidate AS(INSERT INTO deployment_candidates(id,body,input_digest) VALUES($1,'{}',repeat('a',64)) RETURNING id), release AS(INSERT INTO deployment_releases(id,state) SELECT id,'succeeded' FROM candidate RETURNING id) INSERT INTO deployment_runtime(id,release_id,artifact_id,version) SELECT true,id,$2,$3 FROM release`, releaseID, artifact, releaseID+"/g1"); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := p.QueryRow(t.Context(), `SELECT current_schema()`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for i, nodeID := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		principal := fmt.Sprintf("%s_origin_%d", schema, i)
		quoted := pgx.Identifier{principal}.Sanitize()
		if _, err := p.Exec(t.Context(), `CREATE ROLE `+quoted+` LOGIN PASSWORD 'fixture-only'`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP OWNED BY `+quoted+`;DROP ROLE `+quoted) })
		ref := domain.NodeRef{ID: nodeID, Epoch: 1}
		images := map[string]string{}
		protocols := map[string]uint32{}
		for _, role := range []string{"nginx", "management", "background-jobs", "log-query"} {
			images[role] = image
			protocols[role] = 1
		}
		proof := nodes.Observation{EventID: uuid.NewString(), Node: ref, ReleaseID: releaseID, ArtifactID: artifact, Generation: "g1", ImageDigest: image, ObservedAt: time.Now().UTC(), State: "succeeded"}
		registration := nodes.NodeRegistration{Node: ref, Principal: principal, RuntimeProtocol: 1, BootFormat: 1, BootArtifactID: artifact, BridgeImages: images, RoleProtocols: protocols, Original: &proof}
		err := postgres.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error { _, err := owner.RegisterWithin(sc, registration); return err })
		if i == 0 && err != nil {
			t.Fatal("verified original did not adopt its own legacy receipt", err)
		}
		if i == 1 && err == nil {
			t.Fatal("second node copied the singleton receipt without its own actual load")
		}
	}
	var count int
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM deployment_node_runtime`).Scan(&count); err != nil || count != 1 {
		t.Fatal("legacy proof fabricated multiple serving nodes", err)
	}
}
