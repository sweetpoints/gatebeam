package acme

import (
	"encoding/json"
	app "gatebeam/internal/modules/pki/application/acme"
	"gatebeam/internal/modules/pki/domain"
	"net/http"
	"net/mail"
	"strings"
)

func contactProblem(contacts []string) string {
	if len(contacts) > 10 {
		return "invalidContact"
	}
	for _, v := range contacts {
		if len(v) > 254 {
			return "invalidContact"
		}
		if !strings.HasPrefix(v, "mailto:") {
			return "unsupportedContact"
		}
		// RFC8555 section7.3 forbids mailto hfields and multiple addr-specs.
		// Raw query/fragment delimiters are not part of the mailbox.
		if strings.ContainsAny(v, "?#") {
			return "invalidContact"
		}
		a, e := mail.ParseAddress(strings.TrimPrefix(v, "mailto:"))
		if e != nil || a.Address != strings.TrimPrefix(v, "mailto:") {
			return "invalidContact"
		}
	}
	return ""
}
func (s *Server) accountJSON(w http.ResponseWriter, base string, a domain.Account, status int, binding json.RawMessage) {
	w.Header().Set("Location", base+"account/"+a.ID)
	contacts := a.Contacts
	if contacts == nil {
		contacts = []string{}
	}
	response := map[string]any{"status": a.Status, "contact": contacts, "orders": base + "account/" + a.ID + "/orders"}
	if len(binding) > 0 {
		response["externalAccountBinding"] = binding
	}
	s.json(w, status, response)
}
func (s *Server) register(w http.ResponseWriter, r *http.Request, d, base string, key app.PublicKey, payload []byte) {
	var in struct {
		Contacts     []string        `json:"contact"`
		OnlyExisting bool            `json:"onlyReturnExisting"`
		Binding      json.RawMessage `json:"externalAccountBinding"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &in) != nil {
		s.problem(w, 400, "malformed")
		return
	}
	// An existing key is account recovery, not a second EAB registration. Ignore
	// account creation fields for that path as required by RFC8555 section7.3.
	existing, e := s.accounts.Lookup(r.Context(), d, "", key.Thumbprint)
	if e == nil {
		a, e := s.accounts.Current(r.Context(), d, existing.ID, key.Thumbprint, nil, false)
		if e != nil {
			s.fail(w, e)
			return
		}
		s.accountJSON(w, base, a, 200, nil)
		return
	}
	if kind := contactProblem(in.Contacts); kind != "" {
		s.problem(w, 400, kind)
		return
	}
	input := app.Registration{Directory: d, Key: key, OnlyExisting: in.OnlyExisting, Contacts: in.Contacts}
	if len(in.Binding) > 0 && string(in.Binding) != "null" {
		binding, e := parseEnvelope(in.Binding, false)
		if e != nil {
			s.fail(w, e)
			return
		}
		input.BindingID = binding.header.KeyID
		input.Proof = bindingProof{binding, s.crypto, base + "new-account"}
	}
	a, created, e := s.accounts.Register(r.Context(), input)
	if e != nil {
		s.fail(w, e)
		return
	}
	status := 200
	var verifiedBinding json.RawMessage
	if created {
		status = 201
		// Register returned only after verification, atomic binding and COMMIT.
		// Echo the submitted public JWS, never the EAB HMAC secret.
		verifiedBinding = in.Binding
	}
	s.accountJSON(w, base, a, status, verifiedBinding)
}
func (s *Server) account(w http.ResponseWriter, r *http.Request, d, base string, a domain.Account, key app.PublicKey, payload []byte) {
	var in struct {
		Contacts []string        `json:"contact"`
		Status   json.RawMessage `json:"status"`
	}
	if len(payload) > 0 && json.Unmarshal(payload, &in) != nil {
		s.problem(w, 400, "malformed")
		return
	}
	if kind := contactProblem(in.Contacts); kind != "" {
		s.problem(w, 400, kind)
		return
	}
	// RFC8555 section7.3.2 ignores status updates except explicit deactivation.
	var requestedStatus string
	_ = json.Unmarshal(in.Status, &requestedStatus)
	out, e := s.accounts.Current(r.Context(), d, a.ID, key.Thumbprint, in.Contacts, requestedStatus == "deactivated")
	if e != nil {
		s.fail(w, e)
		return
	}
	s.accountJSON(w, base, out, 200, nil)
}
func (s *Server) rollover(w http.ResponseWriter, r *http.Request, d, base string, a domain.Account, old app.PublicKey, payload []byte) {
	inner, e := parseEnvelope(payload, false)
	if e != nil || inner.header.URL != base+"key-change" || len(inner.header.Key) == 0 {
		s.problem(w, 400, "malformed")
		return
	}
	next, e := s.crypto.PublicKey(inner.header.Key)
	if e != nil {
		s.problem(w, 400, "badPublicKey")
		return
	}
	body, e := s.crypto.Verify(payload, next.Encoded, false)
	if e != nil {
		s.problem(w, 400, "malformed")
		return
	}
	var change struct {
		Account string          `json:"account"`
		OldKey  json.RawMessage `json:"oldKey"`
	}
	if json.Unmarshal(body, &change) != nil || change.Account != base+"account/"+a.ID {
		s.problem(w, 400, "malformed")
		return
	}
	oldKey, e := s.crypto.PublicKey(change.OldKey)
	if e != nil || oldKey.Thumbprint != old.Thumbprint || next.Thumbprint == old.Thumbprint {
		s.problem(w, 400, "malformed")
		return
	}
	if existing, e := s.accounts.Lookup(r.Context(), d, "", next.Thumbprint); e == nil {
		w.Header().Set("Location", base+"account/"+existing.ID)
		s.problem(w, 409, "malformed")
		return
	}
	out, e := s.accounts.ChangeKey(r.Context(), d, a.ID, old.Thumbprint, next)
	if e != nil {
		s.fail(w, e)
		return
	}
	s.accountJSON(w, base, out, 200, nil)
}
