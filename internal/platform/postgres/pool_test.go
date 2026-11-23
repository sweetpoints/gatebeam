package postgres

import (
	"context"
	"gatebeam/internal/platform/bootstrap"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOpenSanitizesSecretErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dsn")
	secret := "password-never-in-errors"
	if e := os.WriteFile(path, []byte("://"+secret), 0600); e != nil {
		t.Fatal(e)
	}
	_, e := Open(context.Background(), bootstrap.Config{DatabaseFile: path})
	if e == nil || strings.Contains(e.Error(), secret) {
		t.Fatalf("unsafe error: %v", e)
	}
}
