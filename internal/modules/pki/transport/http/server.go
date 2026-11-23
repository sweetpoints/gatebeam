// Package httptransport assembles the private CA's standard protocol routes.
package httptransport

import (
	"gatebeam/internal/modules/pki/transport/acme"
	"net/http"
)

func NewServer() http.Handler {
	return NewServerWithACME(acme.NewServer())
}
func NewServerWithACME(acmeServer http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/acme/", acmeServer)
	// No OCSP/CRL response body is fabricated before those protocols exist.
	unavailable := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "certificate status service is not implemented", http.StatusServiceUnavailable)
	}
	mux.HandleFunc("/ocsp", unavailable)
	mux.HandleFunc("/crl", unavailable)
	return mux
}
