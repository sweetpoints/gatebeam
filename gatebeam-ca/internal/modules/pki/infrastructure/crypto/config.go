// Package pkicrypto handles standard X.509/PKCS encoding and signer capabilities.
package pkicrypto

import (
	"errors"
	"io"
	"os"
)

var ErrIssuer = errors.New("invalid or unavailable CA issuer material")
var ErrCSR = errors.New("certificate request rejected")

// Config is CA-only. IdentityFile must belong exclusively to the CA process.
// CertificateFile is one intermediate; RootFile is public trust, never a key.
type Config struct{ CertificateFile, RootFile, SignerFile, IdentityFile string }

func readFile(path string, private bool) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 1<<20 || (private && info.Mode().Perm()&0077 != 0) {
		return nil, ErrIssuer
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrIssuer
	}
	defer f.Close()
	actual, e := f.Stat()
	if e != nil || !os.SameFile(info, actual) {
		return nil, ErrIssuer
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		return nil, ErrIssuer
	}
	return b, nil
}
