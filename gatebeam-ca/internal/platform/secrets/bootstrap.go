package secrets

import (
	"errors"
	"filippo.io/age"
	"os"
)

// EnsureIdentity creates an explicit new local identity exclusively. Existing
// identities are validated and never replaced, even when malformed or empty.
func EnsureIdentity(path string) error {
	if path == "" {
		return errSecret
	}
	if _, e := os.Lstat(path); e == nil {
		_, e = New(path)
		return e
	} else if !errors.Is(e, os.ErrNotExist) {
		return errSecret
	}
	key, e := age.GenerateX25519Identity()
	if e != nil {
		return errSecret
	}
	f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return errSecret
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, e = f.WriteString(key.String() + "\n"); e != nil {
		return errSecret
	}
	if e = f.Sync(); e != nil {
		return errSecret
	}
	if e = f.Close(); e != nil {
		return errSecret
	}
	ok = true
	return nil
}
