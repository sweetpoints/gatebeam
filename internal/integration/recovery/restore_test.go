package recovery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalRecoveryConnectionValidatedBeforeDial(t *testing.T) {
	for _, dsn := range []string{"postgres://user@192.0.2.3/db?sslmode=disable", "postgres://user@example.com/db?sslmode=disable", "postgres://user@127.0.0.1/db?sslmode=prefer", "host=127.0.0.1,192.0.2.4 user=user dbname=db sslmode=disable"} {
		path := filepath.Join(t.TempDir(), "db")
		os.WriteFile(path, []byte(dsn), 0600)
		if _, e := LocalAdminConfig(path); e == nil {
			t.Fatal("remote or fallback recovery connection accepted")
		}
	}
	path := filepath.Join(t.TempDir(), "local")
	os.WriteFile(path, []byte("postgres://user@127.0.0.1/db?sslmode=disable"), 0600)
	if _, e := LocalAdminConfig(path); e != nil {
		t.Fatal("explicit loopback refused", e)
	}
}
