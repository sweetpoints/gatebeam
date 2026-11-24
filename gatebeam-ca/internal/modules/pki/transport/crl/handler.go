package crltransport

import (
	"context"
	"gatebeam-ca/internal/modules/pki/domain"
	"net/http"
	"strings"
)

type Service interface {
	CRL(context.Context, domain.IssuerID) ([]byte, error)
}
type Handler struct{ service Service }

func New(s Service) *Handler { return &Handler{s} }
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(405)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/crl/")
	if len(id) != 68 || !strings.HasSuffix(id, ".der") {
		http.NotFound(w, r)
		return
	}
	der, e := h.service.CRL(r.Context(), domain.IssuerID(strings.TrimSuffix(id, ".der")))
	if e != nil {
		http.Error(w, "CRL unavailable", 503)
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Write(der)
}

type RootReader interface {
	ReadRootCRL(context.Context) ([]byte, error)
}

func NewRoot(reader RootReader) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(405)
			return
		}
		b, e := reader.ReadRootCRL(r.Context())
		if e != nil {
			http.Error(w, "root CRL unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Write(b)
	})
}
