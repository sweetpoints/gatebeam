package ocspcache

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// The following types follow RFC6960 section 4; no private wire extension is
// accepted. x/crypto/ocsp verifies the signature; these retain complete CertID
// and nonce fields which that package's public response type does not expose.
type certID struct {
	Algorithm         pkix.AlgorithmIdentifier
	NameHash, KeyHash []byte
	Serial            *big.Int
}
type singleRequest struct {
	Cert       certID
	Extensions []pkix.Extension `asn1:"explicit,tag:0,optional"`
}
type requestData struct {
	Version    int           `asn1:"explicit,tag:0,default:0,optional"`
	Requestor  asn1.RawValue `asn1:"explicit,tag:1,optional"`
	Requests   []singleRequest
	Extensions []pkix.Extension `asn1:"explicit,tag:2,optional"`
}
type wireRequest struct {
	Data      requestData
	Signature asn1.RawValue `asn1:"explicit,tag:0,optional"`
}
type revokedInfo struct {
	At     time.Time       `asn1:"generalized"`
	Reason asn1.Enumerated `asn1:"explicit,tag:0,optional"`
}
type singleResponse struct {
	Cert       certID
	Good       asn1.Flag        `asn1:"tag:0,optional"`
	Revoked    revokedInfo      `asn1:"tag:1,optional"`
	Unknown    asn1.Flag        `asn1:"tag:2,optional"`
	ThisUpdate time.Time        `asn1:"generalized"`
	NextUpdate time.Time        `asn1:"generalized,explicit,tag:0,optional"`
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}
type responseData struct {
	Raw        asn1.RawContent
	Version    int `asn1:"optional,default:0,explicit,tag:0"`
	Responder  asn1.RawValue
	ProducedAt time.Time `asn1:"generalized"`
	Responses  []singleResponse
	Extensions []pkix.Extension `asn1:"explicit,tag:1,optional"`
}

var nonceOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 2}

func nonce(extensions []pkix.Extension) ([]byte, error) {
	var result []byte
	for _, ext := range extensions {
		if !ext.Id.Equal(nonceOID) || result != nil {
			return nil, ErrUnsafe
		}
		var n []byte
		rest, err := asn1.Unmarshal(ext.Value, &n)
		if err != nil || len(rest) != 0 || len(n) < 1 || len(n) > 32 {
			return nil, ErrUnsafe
		}
		result = n
	}
	return result, nil
}
func sameID(a, b certID) bool {
	return a.Serial != nil && b.Serial != nil && a.Serial.Cmp(b.Serial) == 0 && a.Algorithm.Algorithm.Equal(b.Algorithm.Algorithm) && bytes.Equal(a.NameHash, b.NameHash) && bytes.Equal(a.KeyHash, b.KeyHash)
}
