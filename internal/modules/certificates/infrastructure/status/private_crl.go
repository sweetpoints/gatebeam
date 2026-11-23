package status

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
)

// PrivateCRLs fetches only operator-pinned endpoints for explicitly trusted
// issuer certificates. A peer certificate cannot choose an outbound address.
type PrivateCRLs struct{ sources []cacheSource }

func NewPrivateCRLs(profiles []Profile, trust []byte) (*PrivateCRLs, error) {
	c, e := New(profiles)
	if e != nil {
		return nil, e
	}
	out := &PrivateCRLs{}
	seen := map[string]bool{}
	issuers := map[string]cacheSource{}
	for len(bytes.TrimSpace(trust)) > 0 {
		block, rest := pem.Decode(trust)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, ErrStatus
		}
		issuer, e := x509.ParseCertificate(block.Bytes)
		if e != nil || !issuer.IsCA {
			return nil, ErrStatus
		}
		fp := fingerprint(issuer)
		found := false
		for _, p := range c.profiles {
			endpoint := p.profile.CRLURLs[fp]
			if endpoint != "" {
				if old, ok := issuers[fp]; ok && (old.endpoint != endpoint || old.profile.digest != p.digest) {
					return nil, ErrStatus
				}
				issuers[fp] = cacheSource{profile: p, endpoint: endpoint}
				if !seen[endpoint] {
					out.sources = append(out.sources, cacheSource{profile: p, endpoint: endpoint})
					seen[endpoint] = true
				}
				found = true
			}
		}
		if !found {
			return nil, ErrStatus
		}
		trust = rest
	}
	if len(out.sources) == 0 || len(out.sources) > 20 {
		return nil, ErrStatus
	}
	return out, nil
}
func (s *PrivateCRLs) Fetch(ctx context.Context) ([]byte, error) {
	var out []byte
	for _, source := range s.sources {
		raw, e := fetch(ctx, source.profile.client, source.endpoint, nil)
		if e != nil {
			return nil, e
		}
		if block, _ := pem.Decode(raw); block == nil {
			raw = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})
		}
		out = append(out, raw...)
		if len(out) > 1<<20 {
			return nil, ErrStatus
		}
	}
	return out, nil
}
