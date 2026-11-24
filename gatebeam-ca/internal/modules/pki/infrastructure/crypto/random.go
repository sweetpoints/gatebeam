package pkicrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

type Random struct{}

func (Random) Random() (string, error) {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (Random) Digest(s string) string {
	b := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(b[:])
}
