package age

import (
	"context"
	"filippo.io/age"
	"os"
	"path/filepath"
	"testing"
)

func TestOfflineRecoveryIdentityCannotBePackedAsOnlineSecret(t *testing.T) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "api"), 0700)
	key, _ := age.GenerateX25519Identity()
	path := filepath.Join(t.TempDir(), "key")
	os.WriteFile(path, []byte(key.String()), 0600)
	if e := ExportCapsule(context.Background(), dir, "api", "epoch", key.Recipient().String(), map[string]string{"identity.agekey": path}); e == nil {
		t.Fatal("offline recovery identity exported in online capsule")
	}
}
