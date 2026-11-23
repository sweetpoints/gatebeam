package credential

import (
	"regexp"
	"testing"
)

func TestResourceUUIDsAreDistinctFromOpaqueBearers(t *testing.T) {
	c := New()
	seen := map[string]bool{}
	uuid := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	for range 100 {
		id, e := c.NewID()
		if e != nil {
			t.Fatal(e)
		}
		if !uuid.MatchString(id) || seen[id] {
			t.Fatal("invalid or repeated resource UUID", id)
		}
		seen[id] = true
	}
	bearer, e := c.Random()
	if e != nil {
		t.Fatal(e)
	}
	if len(bearer) != 43 || uuid.MatchString(bearer) {
		t.Fatal("bearer entropy/encoding changed")
	}
}
