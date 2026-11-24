package pkicrypto

import (
	"context"
	"errors"
	"gatebeam-ca/internal/platform/secrets"
	"os"
	"path/filepath"
	"syscall"
)

// RewrapOnlineSigners changes only standard age recipients for the two online
// signer files. It never reads the offline root private key. Each replacement
// retains the original holder, so interruption cannot strand the current CA.
func RewrapOnlineSigners(ctx context.Context, cfg Config, rootOCSPKey string, recipients []string) error {
	if _, e := LoadIssuer(cfg); e != nil {
		return e
	}
	secret, e := secrets.NewRoleStore(cfg.IdentityFile, recipients)
	if e != nil {
		return e
	}
	parent := filepath.Dir(cfg.SignerFile)
	canonical, e := filepath.EvalSymlinks(parent)
	if e != nil || canonical != parent || filepath.Dir(rootOCSPKey) != parent || cfg.SignerFile == rootOCSPKey {
		return ErrIssuer
	}
	fd, e := syscall.Open(filepath.Join(parent, ".rewrap.lock"), syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		return e
	}
	defer syscall.Close(fd)
	if e = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return e
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)
	type replacement struct{ path, temp string }
	var staged []replacement
	defer func() {
		for _, file := range staged {
			_ = os.Remove(file.temp)
		}
	}()
	for _, file := range []struct{ path, label string }{{cfg.SignerFile, "pki-online-issuer"}, {rootOCSPKey, "pki-root-ocsp"}} {
		if e = ctx.Err(); e != nil {
			return e
		}
		cipher, e := readFile(file.path, true)
		if e != nil {
			return e
		}
		plain, e := secret.Open(file.label, cipher)
		if e != nil {
			return ErrIssuer
		}
		if _, e = parseKey(plain); e != nil {
			clear(plain)
			return e
		}
		rewrapped, e := secret.Seal(file.label, plain)
		clear(plain)
		if e != nil {
			return e
		}
		temp, e := os.CreateTemp(parent, ".signer-rewrap-")
		if e != nil {
			return e
		}
		staged = append(staged, replacement{file.path, temp.Name()})
		if e = temp.Chmod(0600); e == nil {
			_, e = temp.Write(rewrapped)
		}
		if e == nil {
			e = temp.Sync()
		}
		e = errors.Join(e, temp.Close())
		if e != nil {
			return e
		}
	}
	for _, file := range staged {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = os.Rename(file.temp, file.path); e != nil {
			return e
		}
	}
	directory, e := os.Open(parent)
	if e != nil {
		return e
	}
	defer directory.Close()
	return directory.Sync()
}
