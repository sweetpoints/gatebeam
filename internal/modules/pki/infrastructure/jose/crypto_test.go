package jose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	jose "github.com/go-jose/go-jose/v4"
	"testing"
)

func TestPublicKeyBoundsAndAlgorithmPolicy(t *testing.T) {
	c := Crypto{}
	ec, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	public, _ := json.Marshal(jose.JSONWebKey{Key: &ec.PublicKey})
	if _, e = c.PublicKey(public); e != nil {
		t.Fatal(e)
	}
	private, _ := json.Marshal(jose.JSONWebKey{Key: ec})
	if _, e = c.PublicKey(private); e == nil {
		t.Fatal("private JWK accepted")
	}
	small, e := rsa.GenerateKey(rand.Reader, 1024)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ := json.Marshal(jose.JSONWebKey{Key: &small.PublicKey})
	if _, e = c.PublicKey(encoded); e == nil {
		t.Fatal("weak RSA accepted")
	}
	unsupported, e := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	encoded, _ = json.Marshal(jose.JSONWebKey{Key: &unsupported.PublicKey})
	if _, e = c.PublicKey(encoded); e == nil {
		t.Fatal("unbounded curve policy")
	}
	macKey := make([]byte, 32)
	_, _ = rand.Read(macKey)
	signer, e := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: macKey}, nil)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := signer.Sign([]byte("owned"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = c.Verify([]byte(signed.FullSerialize()), public, false); e == nil {
		t.Fatal("MAC accepted as account signature")
	}
	if _, e = c.Verify([]byte(signed.FullSerialize()), macKey, true); e != nil {
		t.Fatal("valid EAB MAC rejected", e)
	}
	macKey[0] ^= 1
	if _, e = c.Verify([]byte(signed.FullSerialize()), macKey, true); e == nil {
		t.Fatal("invalid EAB MAC accepted")
	}
}
