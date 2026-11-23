package certificates

import (
	"crypto/x509"
	"encoding/json"
	"gatebeam/internal/modules/certificates/application/statuscache"
	"gatebeam/internal/modules/certificates/infrastructure/ocspcache"
	"gatebeam/internal/modules/certificates/infrastructure/status"
	"io"
	"os"
)

func NewOfflineStatusCache(root string) (*statuscache.Service, error) {
	store, err := ocspcache.NewStore(root)
	if err != nil {
		return nil, err
	}
	verifier, err := ocspcache.NewVerifier(nil)
	if err != nil {
		return nil, err
	}
	return statuscache.New(store, verifier, nil)
}

// A missing optional online profile does not invalidate still-fresh signed
// cache entries. It only prevents fetching any new status until control recovers.
func ConfigureOfflineStatusCache(service *statuscache.Service, issuers [][]byte, path string) error {
	if err := service.AddIssuers(issuers); err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 65537))
	decoder.DisallowUnknownFields()
	var profiles []status.Profile
	if decoder.Decode(&profiles) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil
	}
	var certificates []*x509.Certificate
	for _, der := range service.Issuers() {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		certificates = append(certificates, cert)
	}
	fetcher, err := status.NewCacheFetcher(profiles, certificates)
	if err == nil {
		service.SetFetcher(fetcher)
	}
	return nil
}
