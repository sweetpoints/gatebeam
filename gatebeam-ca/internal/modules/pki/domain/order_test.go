package domain

import (
	"testing"
	"time"
)

func TestOrderProofAndCSRNames(t *testing.T) {
	now := time.Now()
	p := Principal{ID: "p", Directory: "server", Names: []string{"a.example", "b.example"}, Usage: ServerAuth, Expires: now.Add(time.Hour)}
	o, e := NewOrder("o", "a", p, []string{"a.example"}, []Challenge{{ID: "c", Name: "a.example", Token: "token", Status: "pending"}}, now)
	if e != nil {
		t.Fatal(e)
	}
	if o.Ready(now) == nil {
		t.Fatal("unproved order is ready")
	}
	if e = o.CompleteChallenge("c", true, now); e != nil {
		t.Fatal(e)
	}
	if o.Ready(now) != nil || o.MatchCSR([]string{"a.example", "b.example"}) == nil {
		t.Fatal("extra CSR name accepted")
	}
	if o.Authorize(Principal{ID: "p", Directory: "server", Names: []string{"b.example"}, Usage: ServerAuth, Expires: p.Expires}, now) == nil {
		t.Fatal("removed grant name accepted")
	}
	if o.Ready(now.Add(2*time.Hour)) == nil {
		t.Fatal("expired order ready")
	}
}
func TestInvalidChallengeCannotBeRevived(t *testing.T) {
	now := time.Now()
	p := Principal{ID: "p", Directory: "client", Names: []string{"a.example"}, Usage: ClientAuth, Expires: now.Add(time.Hour)}
	o, e := NewOrder("o", "a", p, p.Names, []Challenge{{ID: "c", Name: "a.example", Token: "token", Status: "pending"}}, now)
	if e != nil {
		t.Fatal(e)
	}
	if e = o.CompleteChallenge("c", false, now); e != nil {
		t.Fatal(e)
	}
	if o.Status != "invalid" || o.CompleteChallenge("c", true, now) == nil || o.Complete(now) == nil {
		t.Fatal("failed proof revived")
	}
}
