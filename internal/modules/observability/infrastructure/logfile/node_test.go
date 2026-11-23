package logfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNodeInitializationRefusesUnownedErrorLog(t *testing.T) {
	root := t.TempDir()
	if e := os.WriteFile(filepath.Join(root, "error.log"), []byte("legacy error evidence\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := InitializeNodeVolume(root, "11111111-1111-4111-8111-111111111111"); e == nil {
		t.Fatal("unknown nonempty error log relabelled")
	}
}
