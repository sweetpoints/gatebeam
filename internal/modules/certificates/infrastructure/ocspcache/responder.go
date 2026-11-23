package ocspcache

import (
	"encoding/base64"
	"gatebeam/internal/modules/certificates/application/statuscache"
	"golang.org/x/crypto/ocsp"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

func Handler(service *statuscache.Service) http.Handler {
	slots := make(chan struct{}, 16)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Header().Set("Cache-Control", "no-store")
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.WriteHeader(503)
			_, _ = w.Write(ocsp.TryLaterErrorResponse)
			return
		}
		var der []byte
		var err error
		if r.URL.RawQuery != "" {
			w.WriteHeader(400)
			_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		switch r.Method {
		case http.MethodPost:
			media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if e != nil || media != "application/ocsp-request" || r.URL.Path != "/ocsp" {
				w.WriteHeader(415)
				_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
				return
			}
			der, err = io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
		case http.MethodGet:
			encoded := strings.TrimPrefix(r.URL.Path, "/ocsp/")
			if encoded == r.URL.Path || len(encoded) > 8192 {
				w.WriteHeader(400)
				_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
				return
			}
			der, err = base64.StdEncoding.DecodeString(encoded)
		default:
			w.Header().Set("Allow", "GET, POST")
			w.WriteHeader(405)
			return
		}
		if err != nil {
			w.WriteHeader(400)
			_, _ = w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		response, err := service.Lookup(r.Context(), statuscache.Request{DER: der}, time.Now().UTC())
		if err != nil {
			w.WriteHeader(503)
			_, _ = w.Write(ocsp.TryLaterErrorResponse)
			return
		}
		_, _ = w.Write(response)
	})
}
