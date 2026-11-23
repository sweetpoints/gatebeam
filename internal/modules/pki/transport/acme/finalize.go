package acme

import (
	"encoding/base64"
	"encoding/json"
	app "gatebeam/internal/modules/pki/application/acme"
	"net/http"
)

func (s *Server) finalize(w http.ResponseWriter, r *http.Request, base, id string, ref app.AccountRef, payload []byte) {
	var in struct {
		CSR string `json:"csr"`
	}
	if json.Unmarshal(payload, &in) != nil {
		s.problem(w, 400, "badCSR")
		return
	}
	csr, e := base64.RawURLEncoding.Strict().DecodeString(in.CSR)
	if e != nil || len(csr) == 0 {
		s.problem(w, 400, "badCSR")
		return
	}
	o, e := s.orders.Finalize(r.Context(), ref, id, csr)
	if e != nil {
		s.fail(w, e)
		return
	}
	w.Header().Set("Location", base+"order/"+o.ID)
	s.json(w, 200, orderJSON(base, o))
}
