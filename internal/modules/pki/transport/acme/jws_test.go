package acme

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestJWSWireShapeAndProtectedHeaderRequirements(t *testing.T) {
	encode := func(h map[string]any, extra map[string]any) []byte {
		p, _ := json.Marshal(h)
		wire := map[string]any{"protected": base64.RawURLEncoding.EncodeToString(p), "payload": "", "signature": "AQ"}
		for k, v := range extra {
			wire[k] = v
		}
		b, _ := json.Marshal(wire)
		return b
	}
	base := func() map[string]any {
		return map[string]any{"alg": "ES256", "nonce": "bm9uY2U", "url": "https://ca.example/new-account", "jwk": map[string]string{"kty": "EC"}}
	}
	if _, e := parseEnvelope(encode(base(), nil), true); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"unprotected", "general", "bothKeys", "missingURL", "b64", "crit", "missingNonce"} {
		t.Run(name, func(t *testing.T) {
			h := base()
			extra := map[string]any{}
			switch name {
			case "unprotected":
				extra["header"] = map[string]string{"kid": "id"}
			case "general":
				extra["signatures"] = []any{}
			case "bothKeys":
				h["kid"] = "id"
			case "missingURL":
				delete(h, "url")
			case "b64":
				h["b64"] = false
			case "crit":
				h["crit"] = []string{"custom"}
			case "missingNonce":
				delete(h, "nonce")
			}
			if _, e := parseEnvelope(encode(h, extra), true); e == nil {
				t.Fatal("invalid ACME envelope accepted")
			}
		})
	}
	if _, e := parseEnvelope(encode(base(), nil), false); e == nil {
		t.Fatal("inner JWS nonce accepted")
	}
}
