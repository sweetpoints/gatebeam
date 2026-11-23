package status

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"gatebeam/internal/modules/certificates/application/statuscache"
	"slices"
)

type cacheSource struct {
	profile  bound
	endpoint string
}
type CacheFetcher struct{ sources map[string]cacheSource }

// NewCacheFetcher reuses the operator-owned URLs, DNS and network constraints.
// Neither HTTP input nor a certificate's AIA supplies an outbound destination.
func NewCacheFetcher(profiles []Profile, issuers []*x509.Certificate) (*CacheFetcher, error) {
	client, err := New(profiles)
	if err != nil {
		return nil, err
	}
	fetcher := &CacheFetcher{sources: map[string]cacheSource{}}
	for _, issuer := range issuers {
		sum := sha256.Sum256(issuer.RawSubjectPublicKeyInfo)
		fp := hex.EncodeToString(sum[:])
		for _, profile := range client.profiles {
			if !slices.Contains(profile.profile.Fingerprints, fingerprint(issuer)) {
				continue
			}
			endpoint := profile.profile.OCSPURLs[fingerprint(issuer)]
			if old, ok := fetcher.sources[fp]; ok && (old.endpoint != endpoint || old.profile.digest != profile.digest) {
				return nil, ErrStatus
			}
			fetcher.sources[fp] = cacheSource{profile, endpoint}
		}
	}
	return fetcher, nil
}
func (f *CacheFetcher) Fetch(ctx context.Context, issuer string, request []byte) ([]byte, error) {
	source, ok := f.sources[issuer]
	if !ok || len(request) > 4096 {
		return nil, ErrStatus
	}
	der, err := fetch(ctx, source.profile.client, source.endpoint, request)
	if err != nil || len(der) > statuscache.MaxDER {
		return nil, ErrStatus
	}
	return der, nil
}
