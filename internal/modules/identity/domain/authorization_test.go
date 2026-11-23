package domain

import (
	"testing"
	"time"
)

func TestRoleMatrix(t *testing.T) {
	for _, r := range []Role{Readonly, Editor, Publisher, Admin, "unknown"} {
		for _, a := range []Action{View, Edit, Publish, Manage, "unknown"} {
			want := r == Admin && a == Manage || r.Valid() && a == View || (r == Editor || r == Publisher || r == Admin) && a == Edit || (r == Publisher || r == Admin) && a == Publish
			if r.Allows(a) != want {
				t.Fatalf("%s %s", r, a)
			}
		}
	}
}
func TestGrantAndTokenIntersection(t *testing.T) {
	now := time.Now()
	a := Account{ID: "a", State: Active, AuthVersion: 2}
	token := APIToken{AccountID: "a", AuthVersion: 2, Expires: now.Add(time.Hour), Actions: []string{"view"}, SiteIDs: []string{"site-a"}}
	if token.Validate(a, now) != nil || !token.Allows(View, []string{"site-a"}) {
		t.Fatal("valid denied")
	}
	for _, sites := range [][]string{nil, {"site-b"}, {"site-a", "site-b"}} {
		if token.Allows(View, sites) {
			t.Fatal("scope widened")
		}
	}
	if token.Allows(Publish, []string{"site-a"}) {
		t.Fatal("action widened")
	}
	a.AuthVersion++
	if token.Validate(a, now) == nil {
		t.Fatal("version ignored")
	}
	if Granted(Readonly, []Grant{{Kind: "group", ResourceID: "g"}}, "site-a", nil) {
		t.Fatal("unknown group allowed")
	}
	if !Granted(Readonly, []Grant{{Kind: "group", ResourceID: "g"}}, "site-a", []string{"g"}) {
		t.Fatal("group denied")
	}
}
func TestResourceIDsUseUUIDStrings(t *testing.T) {
	for _, id := range []string{"", "site-a", "../../site", "00000000000040008000000000000001"} {
		if ValidResourceID(id) {
			t.Fatal("invalid resource ID accepted", id)
		}
	}
	if !ValidResourceID("00000000-0000-4000-8000-000000000001") {
		t.Fatal("UUID rejected")
	}
}
