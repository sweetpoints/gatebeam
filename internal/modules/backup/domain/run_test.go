package domain

import (
	"strings"
	"testing"
	"time"
)

func TestBackupPolicyBoundsFreshnessAndRetention(t *testing.T) {
	for _, p := range []Policy{{}, {Retain: time.Hour, MaxAge: time.Hour}, {Retain: 400 * 24 * time.Hour, MaxAge: time.Hour}, {Retain: 24 * time.Hour, MaxAge: 0}} {
		if p.Validate() == nil {
			t.Fatalf("unsafe policy accepted: %+v", p)
		}
	}
	if (Policy{Retain: 30 * 24 * time.Hour, MaxAge: 2 * time.Hour}).Validate() != nil {
		t.Fatal("bounded policy denied")
	}
}
func TestManifestCannotContainTraversalOrUnboundedFiles(t *testing.T) {
	valid := func() Manifest {
		return Manifest{Version: 1, ID: strings.Repeat("a", 64), Created: time.Now(), Snapshot: "1:2:", Epoch: "epoch", Schema: strings.Repeat("b", 64), Files: []File{{Name: "database/identity_accounts.json", Bytes: 1, SHA256: strings.Repeat("c", 64)}}}
	}
	if err := valid().Validate(); err != nil {
		t.Fatal("positive manifest rejected", err)
	}
	for _, name := range []string{"../../etc/passwd", "/etc/passwd", "keys/root-key.pem", "database/identity_accounts.sql"} {
		m := valid()
		m.Files[0].Name = name
		if m.Validate() == nil {
			t.Fatal("unsafe archive entry accepted", name)
		}
	}
	m := valid()
	m.Files[0].Bytes = MaxFile + 1
	if m.Validate() == nil {
		t.Fatal("unbounded file accepted")
	}
}
func TestUnprovedSecurityWatermarkNeverAuthorizesActivation(t *testing.T) {
	for _, v := range []RestoreMode{"", "trusted", "activate", "latest"} {
		if v.Validate() == nil {
			t.Fatal("unproved recovery mode accepted", v)
		}
	}
	if Conservative.Validate() != nil {
		t.Fatal("conservative mode denied")
	}
}
