package acme

import (
	"encoding/json"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/domain"
	"net/http"
	"time"
)

func challengeJSON(base, id string, c domain.Challenge) map[string]any {
	v := map[string]any{"type": "http-01", "url": base + "challenge/" + id + "/" + c.ID, "status": c.Status, "token": c.Token}
	if !c.Validated.IsZero() {
		v["validated"] = c.Validated.UTC().Format(time.RFC3339)
	}
	if c.Status == "invalid" {
		v["error"] = map[string]string{"type": "urn:ietf:params:acme:error:unauthorized", "detail": "HTTP-01 validation failed"}
	}
	return v
}
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, base string, parts []string, ref app.AccountRef, payload []byte) {
	if len(parts) != 3 || len(parts[2]) != 43 {
		s.problem(w, 404, "malformed")
		return
	}
	var o domain.Order
	var e error
	if parts[0] == "challenge" && len(payload) > 0 {
		var v map[string]json.RawMessage
		if json.Unmarshal(payload, &v) != nil || v == nil || len(v) != 0 {
			s.problem(w, 400, "malformed")
			return
		}
		o, e = s.orders.Challenge(r.Context(), ref, parts[1], parts[2])
	} else {
		if len(payload) != 0 {
			s.problem(w, 400, "malformed")
			return
		}
		o, e = s.orders.Order(r.Context(), ref, parts[1])
	}
	if e != nil {
		s.fail(w, e)
		return
	}
	var c domain.Challenge
	for _, v := range o.Challenges {
		if v.ID == parts[2] {
			c = v
			break
		}
	}
	if c.ID == "" {
		s.problem(w, 404, "malformed")
		return
	}
	if parts[0] == "challenge" {
		w.Header().Add("Link", "<"+base+"authorization/"+o.ID+"/"+c.ID+">;rel=\"up\"")
		s.json(w, 200, challengeJSON(base, o.ID, c))
		return
	}
	status := c.Status
	if o.Status == "invalid" {
		status = "invalid"
	}
	s.json(w, 200, map[string]any{"status": status, "expires": o.Expires.UTC().Format(time.RFC3339), "identifier": map[string]string{"type": "dns", "value": c.Name}, "challenges": []any{challengeJSON(base, o.ID, c)}})
}
