//go:build integration

package observability_test

import (
	"context"
	"encoding/json"
	"fmt"
	"gatebeam/internal/integration/statistics"
	"gatebeam/internal/modules/deployment"
	"gatebeam/internal/modules/observability"
	query "gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/logfile"
	observabilitypg "gatebeam/internal/modules/observability/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSameSegmentNamesOnTwoNodesAreDistinct(t *testing.T) {
	pool := testkit.Postgres(t)
	ctx := t.Context()
	nodes := []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}
	roots := []string{t.TempDir(), t.TempDir()}
	spools := []string{t.TempDir(), t.TempDir()}
	for i, root := range roots {
		if e := logfile.InitializeNodeVolume(root, nodes[i]); e != nil {
			t.Fatal(e)
		}
	}
	line := fmt.Sprintf(`{"schema_version":1,"time":"%s","site_id":"33333333-3333-4333-8333-333333333333","request_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","route":"default","method":"GET","status":200,"bytes_sent":12,"request_time":"0.01"}`, time.Now().UTC().Format(time.RFC3339Nano)) + "\n"
	if e := os.WriteFile(filepath.Join(roots[0], "access.log"), []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	// Hard-linking gives the fixture exactly the same dev/inode, content, offset
	// and basename. Separate controlled volume identities simulate separate VMs.
	if e := os.Link(filepath.Join(roots[0], "access.log"), filepath.Join(roots[1], "access.log")); e != nil {
		t.Fatal(e)
	}
	batches := []domain.Batch{}
	for i, root := range roots {
		collector, source, e := observability.NewNodeIngestor(pool, root, spools[i], nodes[i])
		if e != nil {
			t.Fatal(e)
		}
		defer source.Close()
		segments, e := source.Discover(ctx)
		if e != nil || len(segments) != 1 {
			t.Fatal(segments, e)
		}
		batch, e := collector.Ingest(ctx, segments[0])
		if e != nil {
			t.Fatal(e)
		}
		if batch.NodeID != nodes[i] || len(batch.Objects) != 1 || batch.Objects[0].SchemaVersion != 2 || batch.Objects[0].NodeID != nodes[i] || !strings.Contains(batch.Objects[0].Key, "/"+nodes[i]+"/") {
			t.Fatalf("node provenance missing: %+v", batch)
		}
		batches = append(batches, batch)
		if replay, e := collector.Ingest(ctx, segments[0]); e != nil || replay.ID != "" {
			t.Fatal("source replay double counted", replay, e)
		}
	}
	for _, node := range nodes {
		var count int
		if e := pool.QueryRow(ctx, `SELECT count(*) FROM observability_segments WHERE node_id=$1`, node).Scan(&count); e != nil || count != 1 {
			t.Fatal("source cursor node provenance absent", node, count, e)
		}
	}
	if batches[0].ID == batches[1].ID || batches[0].SegmentID == batches[1].SegmentID || batches[0].Objects[0].Key == batches[1].Objects[0].Key {
		t.Fatal("two source nodes collided")
	}
	var requests int64
	if e := pool.QueryRow(ctx, `SELECT sum(requests) FROM observability_stats`).Scan(&requests); e != nil || requests != 2 {
		t.Fatal("multi-node counts lost or duplicated", requests, e)
	}
	if _, source, e := observability.NewNodeIngestor(pool, roots[0], spools[0], nodes[1]); e == nil {
		source.Close()
		t.Fatal("node B adopted node A volume")
	}
	unknown := t.TempDir()
	if e := os.WriteFile(filepath.Join(unknown, "access.log"), []byte(line), 0600); e != nil {
		t.Fatal(e)
	}
	if e := logfile.InitializeNodeVolume(unknown, nodes[0]); e == nil {
		t.Fatal("unproven legacy log silently assigned to A")
	}
}

type nodeQuerySecurity struct{}

func (nodeQuerySecurity) RequireWithin(transaction.Scope, query.ActorRef, []string) error { return nil }

type nodeQueryTargets []query.LocalNode

func (n nodeQueryTargets) TargetsWithin(transaction.Scope) ([]query.LocalNode, error) { return n, nil }
func TestLocalQueryPartsCannotBeClaimedByPeer(t *testing.T) {
	pool := testkit.Postgres(t)
	ctx := t.Context()
	runner := postgres.NewRunner(pool)
	a, b := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	site := "33333333-3333-4333-8333-333333333333"
	now := time.Now().UTC().Truncate(time.Hour)
	for i, node := range []string{a, b} {
		segment := fmt.Sprintf("%064x", i+1)
		object := domain.Object{NodeID: node, SchemaVersion: 2, SiteID: site, Hour: now.Format("2006-01-02/15"), Key: site + "/" + now.Format("2006-01-02/15") + "/" + node + "/" + segment + "-0-1.parquet", Checksum: strings.Repeat("a", 64), Rows: 1, Bytes: 10, MinTime: now, MaxTime: now}
		body, _ := json.Marshal([]domain.Object{object})
		if _, e := pool.Exec(ctx, `INSERT INTO observability_segments(id,physical_id,fingerprint,source_name,node_id) VALUES($1,$1,'owned','access.log',$2)`, segment, node); e != nil {
			t.Fatal(e)
		}
		if _, e := pool.Exec(ctx, `INSERT INTO observability_batches(id,segment_id,start_offset,end_offset,source_checksum,objects,invalid_count,schema_count,oversize_count,node_id) VALUES($1,$1,0,1,'owned',$2,0,0,0,$3)`, segment, body, node); e != nil {
			t.Fatal(e)
		}
	}
	service := query.New(runner, nodeQuerySecurity{}, observabilitypg.New())
	service.SetNodes(nodeQueryTargets{{NodeID: a, Epoch: 1}, {NodeID: b, Epoch: 1}})
	filter := query.Filter{Source: "local", SiteIDs: []string{site}, From: now.Add(-time.Minute), To: now.Add(time.Hour)}
	actor := query.ActorRef{UserID: "owned"}
	job, e := service.Submit(ctx, actor, filter)
	if e != nil {
		t.Fatal(e)
	}
	stores := []*observabilitypg.Store{observabilitypg.NewNodeScope(a, 1), observabilitypg.NewNodeScope(b, 1)}
	claims := []query.Input{}
	for i, store := range stores {
		var in query.Input
		var found bool
		if e = runner.Within(ctx, func(sc transaction.Scope) (e error) { in, found, e = store.ClaimWithin(sc); return }); e != nil || !found {
			t.Fatal("local part not claimable", i, found, e)
		}
		if in.Target.NodeID != []string{a, b}[i] || len(in.Objects) != 1 || in.Objects[0].NodeID != in.Target.NodeID {
			t.Fatal("peer claimed foreign local data", in.Target, in.Objects)
		}
		claims = append(claims, in)
	}
	// B can complete only its own part. A remains unreachable during its upgrade.
	rows := []domain.QueryRow{{NodeID: b, Time: now.Format(time.RFC3339Nano), SiteID: site, RequestID: strings.Repeat("b", 32)}}
	if e = runner.Within(ctx, func(sc transaction.Scope) error { return stores[1].CompleteWithin(sc, claims[0], rows, "") }); e == nil {
		t.Fatal("B completed A's local lease")
	}
	if e = runner.Within(ctx, func(sc transaction.Scope) error { return stores[1].CompleteWithin(sc, claims[1], rows, "") }); e != nil {
		t.Fatal(e)
	}
	if _, e = pool.Exec(ctx, `UPDATE observability_queries SET created_at=clock_timestamp()-interval '2 minutes' WHERE id=$1`, job.ID); e != nil {
		t.Fatal(e)
	}
	if e = runner.Within(ctx, func(sc transaction.Scope) error { return stores[1].ExpireLocalWithin(sc) }); e != nil {
		t.Fatal(e)
	}
	page, e := service.Fetch(ctx, actor, job.ID, "")
	if e != nil || page.Job.Coverage != "local_incomplete" || len(page.Rows) != 1 || page.Rows[0].NodeID != b {
		t.Fatal("unreachable A falsely reported complete", page.Job, len(page.Rows), e)
	}
	cancelled, e := service.Submit(ctx, actor, filter)
	if e != nil {
		t.Fatal(e)
	}
	var active query.Input
	if e = runner.Within(ctx, func(sc transaction.Scope) error { var e error; active, _, e = stores[0].ClaimWithin(sc); return e }); e != nil {
		t.Fatal(e)
	}
	if e = service.Cancel(ctx, actor, cancelled.ID); e != nil {
		t.Fatal(e)
	}
	if e = runner.Within(ctx, func(sc transaction.Scope) error {
		current, e := stores[0].LeaseCurrentWithin(sc, active)
		if current {
			t.Fatal("cancelled part lease still current")
		}
		return e
	}); e != nil {
		t.Fatal(e)
	}
	if e = runner.Within(ctx, func(sc transaction.Scope) error { return stores[0].CompleteWithin(sc, active, nil, "") }); e == nil {
		t.Fatal("cancelled local result accepted")
	}
}

func TestLocalQueryRoleCannotImpersonatePeer(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	var schema string
	if e := p.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema); e != nil {
		t.Fatal(e)
	}
	a, b := "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"
	principal := schema + "_jobs_b"
	quoted := pgx.Identifier{principal}.Sanitize()
	if _, e := p.Exec(ctx, `CREATE ROLE `+quoted+` LOGIN PASSWORD 'fixture-only';GRANT USAGE ON SCHEMA `+pgx.Identifier{schema}.Sanitize()+` TO `+quoted+`;GRANT SELECT ON deployment_nodes,observability_query_parts,observability_queries TO `+quoted+`;GRANT UPDATE ON observability_query_parts TO `+quoted); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP OWNED BY `+quoted+`;DROP ROLE `+quoted) })
	body, _ := json.Marshal(map[string]any{"RolePrincipals": map[string]string{"background-jobs": principal}})
	if _, e := p.Exec(ctx, `INSERT INTO deployment_nodes(id,epoch,principal,registration) VALUES($1,1,$2,$3)`, b, principal+"_edge", body); e != nil {
		t.Fatal(e)
	}
	id := uuid.NewString()
	if _, e := p.Exec(ctx, `INSERT INTO observability_queries(id,state,actor,filter,objects,watermark,scan_bytes,expires_at) VALUES($1,'coordinating','{}','{}','[]',0,0,clock_timestamp()+interval '10 minutes')`, id); e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{a, b} {
		if _, e := p.Exec(ctx, `INSERT INTO observability_query_parts(query_id,node_id,node_epoch) VALUES($1,$2,1)`, id, n); e != nil {
			t.Fatal(e)
		}
	}
	cfg := p.Config().Copy()
	cfg.ConnConfig.User = principal
	cfg.ConnConfig.Password = "fixture-only"
	peer, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	// A self-reported node id, even in direct SQL, cannot override session_user.
	changed, e := peer.Exec(ctx, `UPDATE observability_query_parts SET state='running' WHERE node_id=$1`, a)
	if e != nil || changed.RowsAffected() != 0 {
		t.Fatal("peer wrote A", changed, e)
	}
	changed, e = peer.Exec(ctx, `UPDATE observability_query_parts SET state='running' WHERE node_id=$1`, b)
	if e != nil || changed.RowsAffected() != 1 {
		t.Fatal("own registered part denied", changed, e)
	}
	if _, e = p.Exec(ctx, `UPDATE deployment_nodes SET epoch=2 WHERE id=$1`, b); e != nil {
		t.Fatal(e)
	}
	changed, e = peer.Exec(ctx, `UPDATE observability_query_parts SET state='succeeded' WHERE node_id=$1`, b)
	if e != nil || changed.RowsAffected() != 0 {
		t.Fatal("old incarnation wrote result", changed, e)
	}
}

func TestLegacyArchiveMappingRequiresRegisteredOriginalAndCompletedLocalDrain(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	node := "11111111-1111-4111-8111-111111111111"
	if e := observability.MapLegacyArchives(ctx, p, node, map[string]string{"unproved": "checksum"}, statistics.Nodes{Registry: deployment.NewNodes()}); e == nil {
		t.Fatal("unregistered source adopted legacy history")
	}
	if _, e := p.Exec(ctx, `INSERT INTO deployment_nodes(id,epoch,principal,registration,legacy_origin) VALUES($1,1,'fixture-original','{}',true)`, node); e != nil {
		t.Fatal(e)
	}
	at := time.Now().UTC()
	site := "33333333-3333-4333-8333-333333333333"
	id := strings.Repeat("a", 64)
	obj := domain.Object{SchemaVersion: 1, SiteID: site, Hour: at.Format("2006-01-02/15"), Key: site + "/" + at.Format("2006-01-02/15") + "/" + id + ".parquet", Checksum: id, Bytes: 1, Rows: 1, MinTime: at, MaxTime: at}
	r := observabilitypg.New()
	if e := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		seg := domain.Segment{ID: id, Fingerprint: "owned", Path: "access.log", Size: 1}
		if _, e := r.CursorWithin(sc, seg); e != nil {
			return e
		}
		batch := domain.Batch{ID: id, SegmentID: id, End: 1, Objects: []domain.Object{obj}}
		if e := r.CommitWithin(sc, seg, batch); e != nil {
			return e
		}
		return r.CommitManifestWithin(sc, domain.Manifest{BatchID: id, Objects: batch.Objects})
	}); e != nil {
		t.Fatal(e)
	}
	if e := observability.MapLegacyArchives(ctx, p, node, map[string]string{obj.Key: obj.Checksum}, statistics.Nodes{Registry: deployment.NewNodes()}); e == nil {
		t.Fatal("live unarchived/uncleaned source was relabelled")
	}
	if _, e := p.Exec(ctx, `UPDATE observability_batches SET local_cleaned=true`); e != nil {
		t.Fatal(e)
	}
	if e := observability.MapLegacyArchives(ctx, p, node, map[string]string{obj.Key: obj.Checksum}, statistics.Nodes{Registry: deployment.NewNodes()}); e != nil {
		t.Fatal(e)
	}
	var raw []byte
	if e := p.QueryRow(ctx, `SELECT metadata FROM observability_archive_objects`).Scan(&raw); e != nil {
		t.Fatal(e)
	}
	if e := json.Unmarshal(raw, &obj); e != nil || obj.NodeID != node || obj.SchemaVersion != 1 || !domain.ValidObject(obj) {
		t.Fatal("legacy bytes/key must remain readable with proved metadata", obj, e)
	}
}
