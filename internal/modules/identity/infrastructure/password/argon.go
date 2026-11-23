// Package password supplies versioned Argon2id hashes with bounded parsing.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"strings"
)

type Hasher struct{}

func New() *Hasher { return &Hasher{} }

// Parameters are versioned in the PHC string; successful legacy verification asks the application to upgrade.
func (h *Hasher) Hash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=2$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func (h *Hasher) Verify(encoded, password string) (bool, bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false, false
	}
	var memory, iterations uint32
	var parallel uint8
	if _, e := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallel); e != nil || memory < 8192 || memory > 65536 || iterations < 1 || iterations > 3 || parallel < 1 || parallel > 2 {
		return false, false
	}
	salt, e := base64.RawStdEncoding.DecodeString(parts[4])
	if e != nil || len(salt) != 16 {
		return false, false
	}
	key, e := base64.RawStdEncoding.DecodeString(parts[5])
	if e != nil || len(key) != 32 {
		return false, false
	}
	candidate := argon2.IDKey([]byte(password), salt, iterations, memory, parallel, 32)
	ok := subtle.ConstantTimeCompare(key, candidate) == 1
	return ok, ok && (memory != 65536 || iterations != 3 || parallel != 2)
}
