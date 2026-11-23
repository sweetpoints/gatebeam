//go:build integration

package composition

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWebPKICommandRetainsPartialWriteUntilItIsComplete(t *testing.T) {
	path := filepath.Join(t.TempDir(), "command")
	w, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.WriteString(`{"Action":"mfa","Request":`); err != nil {
		t.Fatal(err)
	}
	if _, ok := consumeWebPKICommand(path); ok {
		t.Fatal("partial command was executed")
	}
	if _, err = os.Stat(path); err != nil {
		t.Fatal("a partial command was removed before its writer finished", err)
	}
	if _, err = w.WriteString(`3,"Revision":0}`); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	command, ok := consumeWebPKICommand(path)
	if !ok || command.Action != "mfa" || command.Request != 3 {
		t.Fatal("completed command was lost or changed", ok, command.Request)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("consumed command was not removed", err)
	}
	if _, ok := consumeWebPKICommand(path); ok {
		t.Fatal("completed command was consumed twice")
	}
}
