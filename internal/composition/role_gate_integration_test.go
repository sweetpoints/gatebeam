//go:build integration

package composition

import (
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"github.com/google/uuid"
	"os"
	"path/filepath"
	"testing"
)

func TestHistoricalRoleGateRejectsAOnlyTOTPBeforeTakeover(t *testing.T) {
	p := testkit.Postgres(t)
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	if e := secrets.EnsureIdentity(filepath.Join(dir, "a")); e != nil {
		t.Fatal(e)
	}
	if e := secrets.EnsureIdentity(filepath.Join(dir, "b")); e != nil {
		t.Fatal(e)
	}
	a, e := secrets.New(filepath.Join(dir, "a"))
	if e != nil {
		t.Fatal(e)
	}
	b, e := secrets.New(filepath.Join(dir, "b"))
	if e != nil {
		t.Fatal(e)
	}
	id := uuid.NewString()
	cipher, e := a.Seal("identity/totp/"+id, []byte("owned-history"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, id, cipher); e != nil {
		t.Fatal(e)
	}
	cfg := bootstrap.Config{Mode: "api", RuntimeProtocol: 1, IdentityFile: filepath.Join(dir, "b"), EncryptionRecipients: secrets.RolePolicy{"api": []string{a.Recipient(), b.Recipient()}}}
	if verifyRoleHistory(t.Context(), cfg, p) == nil {
		t.Fatal("B without historical decryption accepted for takeover", b.Recipient())
	}
	cfg.IdentityFile = filepath.Join(dir, "a")
	if e = verifyRoleHistory(t.Context(), cfg, p); e != nil {
		t.Fatal(e)
	}
}
