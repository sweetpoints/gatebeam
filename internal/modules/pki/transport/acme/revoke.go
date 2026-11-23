package acme

import (
	"context"
	"encoding/base64"
	"encoding/json"
	app "gatebeam/internal/modules/pki/application/acme"
	"gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/modules/pki/domain"
	"net/http"
)

type Revocations interface {
	RevokeCertificate(context.Context, status.Request) error
}

// SetRevocations is assembly-only, before the server accepts requests.
func (s *Server) SetRevocations(service Revocations) { s.revocations = service }
func (s *Server) revoke(w http.ResponseWriter, r *http.Request, directory string, account domain.Account, key app.PublicKey, payload []byte) {
	if s.revocations == nil {
		s.problem(w, 503, "serverInternal")
		return
	}
	var in struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}
	if json.Unmarshal(payload, &in) != nil || in.Certificate == "" {
		s.problem(w, 400, "malformed")
		return
	}
	der, e := base64.RawURLEncoding.DecodeString(in.Certificate)
	if e != nil || len(der) > 65536 {
		s.problem(w, 400, "malformed")
		return
	}
	e = s.revocations.RevokeCertificate(r.Context(), status.Request{Directory: directory, AccountID: account.ID, Thumbprint: key.Thumbprint, Key: key.Encoded, Certificate: der, Reason: in.Reason})
	if e != nil {
		s.fail(w, e)
		return
	}
	w.WriteHeader(200)
}
