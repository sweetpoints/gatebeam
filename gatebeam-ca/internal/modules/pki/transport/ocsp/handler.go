// Package ocsptransport is the RFC6960 DER HTTP boundary.
package ocsptransport

import (
	"context"
	"encoding/base64"
	"fmt"
	"gatebeam-ca/internal/modules/pki/application/status"
	"gatebeam-ca/internal/modules/pki/domain"
	"golang.org/x/crypto/ocsp"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type Service interface {
	OCSP(context.Context, status.CertID) ([]byte, error)
}
type Handler struct{ service Service }

func New(s Service) *Handler { return &Handler{s} }
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Header().Set("Cache-Control", "no-store")
	var der []byte
	var e error
	switch r.Method {
	case "GET":
		encoded := strings.TrimPrefix(r.URL.Path, "/ocsp/")
		if len(encoded) > 8192 || encoded == r.URL.Path {
			w.WriteHeader(400)
			w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		der, e = base64.StdEncoding.DecodeString(encoded)
	case "POST":
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/ocsp-request" {
			w.WriteHeader(415)
			w.Write(ocsp.MalformedRequestErrorResponse)
			return
		}
		der, e = io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	default:
		w.Header().Set("Allow", "GET, POST")
		w.WriteHeader(405)
		return
	}
	if e != nil {
		w.WriteHeader(400)
		w.Write(ocsp.MalformedRequestErrorResponse)
		return
	}
	req, e := ocsp.ParseRequest(der)
	if e != nil || req.SerialNumber.Sign() <= 0 || req.SerialNumber.BitLen() > 159 {
		w.WriteHeader(400)
		w.Write(ocsp.MalformedRequestErrorResponse)
		return
	}
	response, e := h.service.OCSP(r.Context(), status.CertID{Hash: req.HashAlgorithm.String(), NameHash: req.IssuerNameHash, KeyHash: req.IssuerKeyHash, Serial: domain.Serial(fmt.Sprintf("%040x", req.SerialNumber))})
	if e != nil {
		if e == status.ErrUnknownIssuer {
			w.WriteHeader(200)
			w.Write(ocsp.UnauthorizedErrorResponse)
		} else {
			w.WriteHeader(503)
			w.Write(ocsp.TryLaterErrorResponse)
		}
		return
	}
	// Signed nextUpdate is the authoritative cache limit. HTTP lifetime is never
	// longer and clients retain their normal OCSP freshness semantics.
	parsed, err := ocsp.ParseResponse(response, nil)
	if err != nil {
		w.WriteHeader(503)
		w.Write(ocsp.TryLaterErrorResponse)
		return
	}
	seconds := int(time.Until(parsed.NextUpdate).Seconds())
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 300 {
		seconds = 300
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(seconds))
	w.WriteHeader(200)
	w.Write(response)
}
