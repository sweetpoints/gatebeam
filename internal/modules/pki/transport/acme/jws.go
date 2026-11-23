package acme

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/pki/application/acme"
)

var errMalformed = errors.New("malformed ACME message")

type protected struct {
	Algorithm string          `json:"alg"`
	Nonce     string          `json:"nonce"`
	URL       string          `json:"url"`
	KeyID     string          `json:"kid"`
	Key       json.RawMessage `json:"jwk"`
}
type envelope struct {
	header protected
	raw    []byte
}

// RFC8555 requires the flattened JSON serialization and protected parameters.
// This parser only enforces wire shape; go-jose performs cryptographic checks.
func parseEnvelope(raw []byte, nonce bool) (envelope, error) {
	var fields map[string]json.RawMessage
	if len(raw) == 0 || len(raw) > 65536 || json.Unmarshal(raw, &fields) != nil || len(fields) != 3 {
		return envelope{}, errMalformed
	}
	for _, k := range []string{"protected", "payload", "signature"} {
		var s string
		if json.Unmarshal(fields[k], &s) != nil {
			return envelope{}, errMalformed
		}
		if _, e := base64.RawURLEncoding.Strict().DecodeString(s); e != nil {
			return envelope{}, errMalformed
		}
	}
	var encoded string
	_ = json.Unmarshal(fields["protected"], &encoded)
	b, e := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if e != nil || len(b) > 16384 {
		return envelope{}, errMalformed
	}
	var h protected
	var hf map[string]json.RawMessage
	if json.Unmarshal(b, &h) != nil || json.Unmarshal(b, &hf) != nil || h.Algorithm == "" || h.URL == "" {
		return envelope{}, errMalformed
	}
	// Extensions capable of changing payload interpretation are unsupported.
	if _, ok := hf["crit"]; ok {
		return envelope{}, errMalformed
	}
	if _, ok := hf["b64"]; ok {
		return envelope{}, errMalformed
	}
	_, hasNonce := hf["nonce"]
	if nonce && (!hasNonce || h.Nonce == "") {
		return envelope{}, app.ErrBadNonce
	}
	if nonce {
		if _, e := base64.RawURLEncoding.Strict().DecodeString(h.Nonce); e != nil {
			return envelope{}, errMalformed
		}
	}
	if !nonce && hasNonce {
		return envelope{}, errMalformed
	}
	_, hasKey := hf["jwk"]
	_, hasID := hf["kid"]
	if hasKey == hasID || (hasID && h.KeyID == "") || (hasKey && len(h.Key) == 0) {
		return envelope{}, errMalformed
	}
	return envelope{h, raw}, nil
}

type bindingProof struct {
	envelope envelope
	crypto   app.Crypto
	url      string
}

func (b bindingProof) VerifyBinding(secret []byte, key app.PublicKey) error {
	h := b.envelope.header
	if h.URL != b.url || h.Algorithm != "HS256" || h.KeyID == "" || len(h.Key) != 0 {
		return errMalformed
	}
	payload, e := b.crypto.Verify(b.envelope.raw, secret, true)
	if e != nil {
		return e
	}
	actual, e := b.crypto.PublicKey(payload)
	if e != nil || actual.Thumbprint != key.Thumbprint {
		return errMalformed
	}
	return nil
}
