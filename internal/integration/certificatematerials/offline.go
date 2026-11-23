package certificatematerials

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"gatebeam/internal/modules/certificates/application/statuscache"
	edge "gatebeam/internal/modules/deployment/application/runtime"
)

const LocalOCSPResponder = "http://127.0.0.1:9091/ocsp"

type OfflineStatus struct {
	Service   *statuscache.Service
	Configure func([][]byte) error
}

func (o *OfflineStatus) Bind(state *edge.RuntimeState) error {
	if o == nil {
		return nil
	}
	var issuers [][]byte
	seen := map[string]bool{}
	for _, material := range state.Materials {
		if material.OCSP == nil {
			continue
		}
		rest := bytes.TrimSpace(material.TrustPEM)
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" {
				return errors.New("invalid authorized OCSP issuer material")
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			fp := hex.EncodeToString(sum[:])
			if !seen[fp] {
				issuers = append(issuers, cert.Raw)
				seen[fp] = true
			}
			rest = bytes.TrimSpace(next)
		}
	}
	if o.Configure != nil {
		if err := o.Configure(issuers); err != nil {
			return err
		}
	} else if err := o.Service.AddIssuers(issuers); err != nil {
		return err
	}
	state.OCSPResponder = LocalOCSPResponder
	return nil
}
