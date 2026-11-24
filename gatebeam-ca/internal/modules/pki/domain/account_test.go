package domain

import (
	"testing"
	"time"
)

func TestBindingExpiryDoesNotExpireAccount(t *testing.T) {
	now := time.Now()
	p := Principal{ID: "p", Names: []string{"host.example"}, Usage: ServerAuth, Directory: "server", Expires: now.Add(time.Hour)}
	if e := p.Authorize("server", now); e != nil {
		t.Fatal(e)
	}
	for _, d := range []string{"client", ""} {
		if p.Authorize(d, now) == nil {
			t.Fatal("wrong directory authorized")
		}
	}
	b := Binding{ID: "b", PrincipalID: "p", Expires: now.Add(15 * time.Minute)}
	if b.Consume(p, "server", now.Add(16*time.Minute)) == nil {
		t.Fatal("expired binding accepted")
	}
	if p.Authorize("server", now.Add(16*time.Minute)) != nil {
		t.Fatal("principal expired with EAB")
	}
	b.Expires = now.Add(time.Hour)
	if b.Consume(p, "server", now) != nil || b.Consume(p, "server", now) == nil {
		t.Fatal("binding not single-use")
	}
	p.Disabled = true
	if p.Authorize("server", now) == nil {
		t.Fatal("disabled principal accepted")
	}
}
func TestGrantCannotWidenPurposeOrNames(t *testing.T) {
	now := time.Now()
	for _, p := range []Principal{
		{ID: "p", Names: []string{"host.example"}, Usage: ClientAuth, Directory: "server", Expires: now.Add(time.Hour)},
		{ID: "p", Names: []string{"*.example"}, Usage: ServerAuth, Directory: "server", Expires: now.Add(time.Hour)},
		{ID: "p", Names: []string{"host.example"}, Usage: ServerAuth, Directory: "server", Expires: now},
	} {
		if p.Validate(now) == nil {
			t.Fatal("invalid grant accepted")
		}
	}
	a := Account{ID: "a", PrincipalID: "p", Directory: "server", Key: []byte("public"), Thumbprint: "old", Status: "valid"}
	if a.ChangeKey("stale", "new", []byte("public-new")) == nil {
		t.Fatal("stale key changed")
	}
	if a.ChangeKey("old", "new", []byte("public-new")) != nil || a.Thumbprint != "new" {
		t.Fatal("rollover failed")
	}
}
