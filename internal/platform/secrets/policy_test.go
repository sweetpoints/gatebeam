package secrets

import (
	"filippo.io/age"
	"testing"
)

func TestRoleRecipientPolicyRejectsCrossRoleKeys(t *testing.T) {
	a, _ := age.GenerateX25519Identity()
	b, _ := age.GenerateX25519Identity()
	if e := ValidateRoleRecipients(map[string][]string{"api": {a.Recipient().String()}, "provider": {a.Recipient().String()}}); e == nil {
		t.Fatal("same identity in different roles")
	}
	if e := ValidateRoleRecipients(map[string][]string{"api": {a.Recipient().String(), b.Recipient().String()}}); e != nil {
		t.Fatal(e)
	}
	if e := ValidateRoleRecipients(map[string][]string{"invented": {"bad"}}); e == nil {
		t.Fatal("invalid role accepted")
	}
}
