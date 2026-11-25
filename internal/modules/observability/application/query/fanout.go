package query

import (
	"gatebeam/internal/modules/observability/domain"
	"sort"
)

// MaxLocalNodes is the largest supported local query fan-out.
const MaxLocalNodes = 32

// NodePart reports one frozen source target. An unavailable local source is
// missing coverage even when every reachable node returned an empty result.
type NodePart struct {
	NodeID, State string
	Rows          []domain.QueryRow
	Error         string
	Truncated     bool
}

func Merge(parts []NodePart, limit int) (rows []domain.QueryRow, coverage string, truncated bool) {
	rows = []domain.QueryRow{}
	coverage = "complete"
	if len(parts) == 0 || len(parts) > MaxLocalNodes || limit < 1 || limit > domain.MaxQueryRows {
		return rows, "incomplete", false
	}
	seen := map[string]bool{}
	nodes := map[string]bool{}
	for _, part := range parts {
		if part.NodeID == "" || nodes[part.NodeID] || part.State != "succeeded" || part.Error != "" {
			coverage = "incomplete"
		}
		nodes[part.NodeID] = true
		if part.State != "succeeded" {
			continue
		}
		if part.Truncated {
			truncated = true
		}
		if len(part.Rows) > domain.MaxQueryRows {
			coverage = "incomplete"
			truncated = true
			continue
		}
		for _, row := range part.Rows {
			node := row.NodeID
			if node == "" {
				node = "legacy"
			}
			key := node + "/" + row.SiteID + "/" + row.RequestID
			if seen[key] {
				continue
			}
			seen[key] = true
			rows = append(rows, row)
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Time != b.Time {
			return a.Time > b.Time
		}
		if a.NodeID != b.NodeID {
			return a.NodeID < b.NodeID
		}
		if a.SiteID != b.SiteID {
			return a.SiteID < b.SiteID
		}
		return a.RequestID < b.RequestID
	})
	if len(rows) > limit {
		rows = rows[:limit]
		truncated = true
	}
	return
}
