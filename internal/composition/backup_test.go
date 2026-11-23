package composition

import (
	"context"
	"encoding/json"
	"filippo.io/age"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"path/filepath"
	"testing"
)

func TestBackupRoleCannotReceiveForeignOrOfflineKeyCapabilities(t *testing.T) {
	for _, mode := range []string{"backup-export", "worker", "api", "ca", "edge"} {
		cfg := bootstrap.Config{Mode: mode, RecoveryIdentityFile: "offline"}
		if bootstrap.ValidateCapabilities(mode, cfg) == nil {
			t.Fatal("offline recovery key accepted", mode)
		}
	}
	for _, cfg := range []bootstrap.Config{{Mode: "backup-export", CAIdentityFile: "ca"}, {Mode: "backup-export", IdentityFile: "api"}, {Mode: "backup-export", CertificateIdentityFile: "edge"}, {Mode: "backup-export", CertificateProviderIdentityFile: "worker"}, {Mode: "backup-export", BackupCredentialsFile: "r2"}} {
		if bootstrap.ValidateCapabilities(cfg.Mode, cfg) == nil {
			t.Fatal("snapshot role received online private-key/upload capability")
		}
	}
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "api"), 0700)
	key, _ := age.GenerateX25519Identity()
	path := filepath.Join(t.TempDir(), "api.key")
	online, _ := age.GenerateX25519Identity()
	os.WriteFile(path, []byte(online.String()), 0600)
	cfg := bootstrap.Config{Mode: "api", IdentityFile: path, APITLSKeyFile: path, BackupRecipient: key.Recipient().String(), BackupEpoch: "epoch", BackupCapsuleDirectory: dir}
	if e := ExportBackupCapsule(context.Background(), cfg); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(filepath.Join(dir, "api", "current.json")); e != nil {
		t.Fatal("role capsule not published", e)
	}
	var ref struct{ Digest string }
	b, e := os.ReadFile(filepath.Join(dir, "api", "current.json"))
	if e != nil || json.Unmarshal(b, &ref) != nil {
		t.Fatal(e)
	}
	ciphertext, e := os.ReadFile(filepath.Join(dir, "api", ref.Digest+".age"))
	if e != nil {
		t.Fatal(e)
	}
	offline := filepath.Join(t.TempDir(), "recovery.key")
	if e = os.WriteFile(offline, []byte(key.String()), 0600); e != nil {
		t.Fatal(e)
	}
	plain, e := archive.Decrypt(ciphertext, offline)
	if e != nil {
		t.Fatal(e)
	}
	var capsule archive.Capsule
	if e = json.Unmarshal(plain, &capsule); e != nil || string(capsule.Files["api-tls.key"]) != online.String() {
		t.Fatal("own TLS key missing from encrypted capsule", e)
	}
	cfg.IdentityFile = ""
	cfg.CASignerFile = path
	if e := ExportBackupCapsule(context.Background(), cfg); e == nil {
		t.Fatal("API capsule exported CA signing key")
	}
}
