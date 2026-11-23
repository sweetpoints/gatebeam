package query

import (
	"gatebeam/internal/modules/observability/domain"
	"testing"
)

func TestLocalQueryUnavailableIsIncomplete(t *testing.T) {
	row := domain.QueryRow{Time: "2026-11-08T00:00:00Z", SiteID: "11111111-1111-4111-8111-111111111111", RequestID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", NodeID: "11111111-1111-4111-8111-111111111111"}
	parts := []NodePart{{NodeID: row.NodeID, State: "succeeded", Rows: []domain.QueryRow{row}}, {NodeID: "22222222-2222-4222-8222-222222222222", State: "unavailable", Error: "query_unavailable"}}
	rows, coverage, truncated := Merge(parts, 100)
	if len(rows) != 1 || coverage != "incomplete" || truncated {
		t.Fatal("unavailable local node appeared complete", len(rows), coverage, truncated)
	}
	parts[1].State = "succeeded"
	parts[1].Error = ""
	parts[1].Rows = []domain.QueryRow{row}
	rows, coverage, truncated = Merge(parts, 1)
	if len(rows) != 1 || coverage != "complete" || truncated {
		t.Fatal("duplicated observation counted as extra truncation", len(rows), coverage, truncated)
	}
	next := row
	next.RequestID = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	next.Time = "2026-11-08T00:00:01Z"
	parts[1].Rows = append(parts[1].Rows, next)
	rows, coverage, truncated = Merge(parts, 1)
	if len(rows) != 1 || rows[0].RequestID != next.RequestID || !truncated || coverage != "complete" {
		t.Fatal("global deterministic limit not enforced", rows, coverage, truncated)
	}
	if rows, coverage, _ = Merge(nil, 100); len(rows) != 0 || coverage != "incomplete" {
		t.Fatal("empty target set declared complete")
	}
}
