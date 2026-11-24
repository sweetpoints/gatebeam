// Package jose uses go-jose for all signature and JWK thumbprint operations.
package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	jose "github.com/go-jose/go-jose/v4"
)

var ErrSignature = errors.New("invalid ACME signature or key")

type Crypto struct{}

func (Crypto) PublicKey(raw []byte) (app.PublicKey, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return app.PublicKey{}, ErrSignature
	}
	var k jose.JSONWebKey
	if json.Unmarshal(raw, &k) != nil || !k.Valid() || !k.IsPublic() {
		return app.PublicKey{}, ErrSignature
	}
	switch p := k.Key.(type) {
	case *rsa.PublicKey:
		if p.N.BitLen() < 2048 || p.N.BitLen() > 4096 || p.E < 65537 {
			return app.PublicKey{}, ErrSignature
		}
	case *ecdsa.PublicKey:
		if p.Curve != elliptic.P256() && p.Curve != elliptic.P384() {
			return app.PublicKey{}, ErrSignature
		}
	default:
		return app.PublicKey{}, ErrSignature
	}
	thumb, e := k.Thumbprint(crypto.SHA256)
	if e != nil {
		return app.PublicKey{}, ErrSignature
	}
	encoded, e := json.Marshal(k.Public())
	if e != nil {
		return app.PublicKey{}, ErrSignature
	}
	return app.PublicKey{Encoded: encoded, Thumbprint: base64.RawURLEncoding.EncodeToString(thumb)}, nil
}
func (c Crypto) Verify(raw, key []byte, mac bool) ([]byte, error) {
	algorithms := []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.RS256}
	var verification any
	if mac {
		if len(key) != 32 {
			return nil, ErrSignature
		}
		algorithms = []jose.SignatureAlgorithm{jose.HS256}
		verification = key
	} else {
		if _, e := c.PublicKey(key); e != nil {
			return nil, e
		}
		var k jose.JSONWebKey
		if json.Unmarshal(key, &k) != nil {
			return nil, ErrSignature
		}
		verification = k.Key
	}
	signed, e := jose.ParseSignedJSON(string(raw), algorithms)
	if e != nil || len(signed.Signatures) != 1 {
		return nil, ErrSignature
	}
	payload, e := signed.Verify(verification)
	if e != nil {
		return nil, ErrSignature
	}
	return payload, nil
}
