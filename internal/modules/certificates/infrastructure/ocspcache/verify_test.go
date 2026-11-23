package ocspcache

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"gatebeam/internal/modules/certificates/application/statuscache"
	"golang.org/x/crypto/ocsp"
	"math/big"
	"testing"
	"time"
)

func TestVerifierBindsNonceCompleteCertIDAndDelegate(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Minute)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cache issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	issuer, _ := x509.ParseCertificate(der)
	verifier, err := NewVerifier([][]byte{der})
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(42)}
	request, _ := ocsp.CreateRequest(leaf, issuer, nil)
	response, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{SerialNumber: leaf.SerialNumber, Status: ocsp.Good, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}, key)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(change func(*responseData)) []byte {
		var outer struct {
			Status   asn1.Enumerated
			Response struct {
				Type asn1.ObjectIdentifier
				DER  []byte
			} `asn1:"explicit,tag:0,optional"`
		}
		if _, err := asn1.Unmarshal(response, &outer); err != nil {
			t.Fatal(err)
		}
		var basic struct {
			Data         responseData
			Algorithm    pkix.AlgorithmIdentifier
			Signature    asn1.BitString
			Certificates []asn1.RawValue `asn1:"explicit,tag:0,optional"`
		}
		if _, err := asn1.Unmarshal(outer.Response.DER, &basic); err != nil {
			t.Fatal(err)
		}
		basic.Data.Raw = nil
		change(&basic.Data)
		tbs, err := asn1.Marshal(basic.Data)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(tbs)
		signature, err := key.Sign(rand.Reader, sum[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}
		basic.Signature = asn1.BitString{Bytes: signature, BitLength: len(signature) * 8}
		outer.Response.DER, err = asn1.Marshal(basic)
		if err != nil {
			t.Fatal(err)
		}
		result, err := asn1.Marshal(outer)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	var wire wireRequest
	if _, err = asn1.Unmarshal(request, &wire); err != nil {
		t.Fatal(err)
	}
	nonceDER, _ := asn1.Marshal([]byte("0123456789abcdef"))
	wire.Data.Extensions = []pkix.Extension{{Id: nonceOID, Value: nonceDER}}
	requestNonce, err := asn1.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	matching := rewrite(func(data *responseData) { data.Extensions = wire.Data.Extensions })
	verdict, err := verifier.Verify(statuscache.Request{DER: requestNonce}, matching, now)
	if err != nil || !verdict.Good {
		t.Fatalf("matching standard nonce rejected: %v", err)
	}
	if _, err = verifier.Verify(statuscache.Request{DER: request}, matching, now); err == nil {
		t.Fatal("nonce response replayed to a different request")
	}
	for _, damage := range []string{"certid-name-hash", "certid-key-hash", "responder-id", "nonce-mismatch"} {
		t.Run(damage, func(t *testing.T) {
			changed := rewrite(func(data *responseData) {
				switch damage {
				case "certid-name-hash":
					data.Responses[0].Cert.NameHash[0] ^= 1
				case "certid-key-hash":
					data.Responses[0].Cert.KeyHash[0] ^= 1
				case "responder-id":
					data.Responder = asn1.RawValue{Class: 2, Tag: 1, IsCompound: true, Bytes: []byte{0x30, 0x00}}
				case "nonce-mismatch":
					n, _ := asn1.Marshal([]byte("wrong-nonce-value"))
					data.Extensions = []pkix.Extension{{Id: nonceOID, Value: n}}
				}
			})
			if _, err := ocsp.ParseResponse(changed, issuer); err != nil {
				t.Fatalf("test response lost its valid CA signature: %v", err)
			}
			if _, err := verifier.Verify(statuscache.Request{DER: request}, changed, now); err == nil {
				t.Fatal("valid signature bypassed request/responder binding")
			}
		})
	}
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newDER, err := x509.CreateCertificate(rand.Reader, template, template, &newKey.PublicKey, newKey)
	if err != nil {
		t.Fatal(err)
	}
	rolled, _ := NewVerifier([][]byte{newDER})
	if _, err = rolled.Request(statuscache.Request{DER: request}); err == nil {
		t.Fatal("issuer rollover accepted request for old key")
	}
	delegateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	delegateTemplate := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "unauthorized delegate"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	delegateDER, _ := x509.CreateCertificate(rand.Reader, delegateTemplate, issuer, &delegateKey.PublicKey, key)
	delegate, _ := x509.ParseCertificate(delegateDER)
	badDelegate, err := ocsp.CreateResponse(issuer, delegate, ocsp.Response{SerialNumber: leaf.SerialNumber, Status: ocsp.Good, ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour), Certificate: delegate}, delegateKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = verifier.Verify(statuscache.Request{DER: request}, badDelegate, now); err == nil {
		t.Fatal("ordinary TLS leaf became an OCSP signing delegate")
	}
}
