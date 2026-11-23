package recovery

import (
	"slices"
	"testing"
)

func TestSchemaContractsAreExplicit(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range []int64{22, 23, 24, 25, 26, 27} {
		c, e := SchemaContract(v)
		if e != nil || c.Version != v || len(c.Digest) != 64 || len(c.Tables) == 0 || seen[c.Digest] {
			t.Fatal(v, c, e)
		}
		seen[c.Digest] = true
		if slices.Contains(c.Tables, "deployment_nodes") != (v >= 24) || slices.Contains(c.Tables, "certificates_node_envelopes") != (v >= 25) || slices.Contains(c.Tables, "observability_query_parts") != (v >= 26) || slices.Contains(c.Tables, "deployment_upgrade_runs") != (v >= 27) {
			t.Fatal("wrong finite table contract", v)
		}
		if e = RestoreCompatibility(v, 27); e != nil {
			t.Fatal(v, e)
		}
		c.Tables[0] = "mutated"
		next, _ := SchemaContract(v)
		if next.Tables[0] == "mutated" {
			t.Fatal("mutable contract leaked")
		}
	}
	for _, v := range []int64{-1, 0, 1, 21, 28, 999} {
		if _, e := SchemaContract(v); e == nil {
			t.Fatal("unknown source accepted", v)
		}
	}
	for _, pair := range [][2]int64{{26, 22}, {22, 25}, {27, 26}, {28, 27}} {
		if e := RestoreCompatibility(pair[0], pair[1]); e == nil {
			t.Fatal("undefined conversion", pair)
		}
	}
}
