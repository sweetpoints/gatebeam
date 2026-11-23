//go:build integration

package postgres

import (
	"gatebeam/internal/modules/observability/domain"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"testing"
)

func TestLogCutoffRequiresAnOwnedCursor(t *testing.T) {
	p := testkit.Postgres(t)
	node := uuid.NewString()
	r := NewNode(node)
	segments := []domain.Segment{{NodeID: node, ID: "owned-physical", Fingerprint: "owned-fingerprint", Size: 12}}
	ready := true
	e := platform.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		var e error
		ready, e = r.VerifyLogCutoff(sc, segments, false)
		return e
	})
	if e != nil || ready {
		t.Fatal("missing cursor falsely flushed", ready, e)
	}
	id := uuid.NewString()
	if _, e = p.Exec(t.Context(), `INSERT INTO observability_segments(id,physical_id,fingerprint,source_offset,node_id,source_name) VALUES($1,$2,$3,12,$4,'access.log')`, id, segments[0].ID, segments[0].Fingerprint, node); e != nil {
		t.Fatal(e)
	}
	e = platform.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
		var e error
		ready, e = r.VerifyLogCutoff(sc, segments, false)
		return e
	})
	if e != nil || !ready {
		t.Fatal("durable cursor not recognized", ready, e)
	}
	batch := uuid.NewString()
	if _, e = p.Exec(t.Context(), `INSERT INTO observability_batches(id,segment_id,start_offset,end_offset,source_checksum,objects,invalid_count,schema_count,oversize_count,node_id) VALUES($1,$2,0,12,'owned','[]',0,0,0,$3)`, batch, id, node); e != nil {
		t.Fatal(e)
	}
	checkArchived := func(want bool) {
		t.Helper()
		e := platform.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error {
			var e error
			ready, e = r.VerifyLogCutoff(sc, segments, true)
			return e
		})
		if e != nil || ready != want {
			t.Fatal("archive cutoff verdict", ready, want, e)
		}
	}
	checkArchived(false)
	if _, e = p.Exec(t.Context(), `INSERT INTO observability_manifests(batch_id,node_id) VALUES($1,$2)`, batch, node); e != nil {
		t.Fatal(e)
	}
	checkArchived(true)
	if _, e = p.Exec(t.Context(), `UPDATE observability_manifests SET state='deleting' WHERE batch_id=$1`, batch); e != nil {
		t.Fatal(e)
	}
	checkArchived(false)
	segments[0].NodeID = uuid.NewString()
	if e = platform.NewRunner(p).Within(t.Context(), func(sc transaction.Scope) error { _, e := r.VerifyLogCutoff(sc, segments, false); return e }); e == nil {
		t.Fatal("foreign cursor accepted")
	}
}
