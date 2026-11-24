package acme

import (
	"context"
	"encoding/json"
	app "gatebeam-ca/internal/modules/pki/application/acme"
	"gatebeam-ca/internal/modules/pki/domain"
	"net/http"
	"strings"
	"time"
)

type Orders interface {
	NewOrder(context.Context, app.AccountRef, []string) (domain.Order, error)
	Order(context.Context, app.AccountRef, string) (domain.Order, error)
	Orders(context.Context, app.AccountRef, string) ([]string, error)
	Challenge(context.Context, app.AccountRef, string, string) (domain.Order, error)
	Finalize(context.Context, app.AccountRef, string, []byte) (domain.Order, error)
	Certificate(context.Context, app.AccountRef, string) (domain.IssuedCertificate, error)
}

func orderJSON(base string, o domain.Order) map[string]any {
	ids := make([]map[string]string, 0, len(o.Names))
	auth := make([]string, 0, len(o.Challenges))
	for _, n := range o.Names {
		ids = append(ids, map[string]string{"type": "dns", "value": n})
	}
	for _, c := range o.Challenges {
		auth = append(auth, base+"authorization/"+o.ID+"/"+c.ID)
	}
	v := map[string]any{"status": o.Status, "expires": o.Expires.UTC().Format(time.RFC3339), "identifiers": ids, "authorizations": auth, "finalize": base + "finalize/" + o.ID}
	if o.Status == "valid" {
		v["certificate"] = base + "certificate/" + o.ID
	}
	return v
}
func (s *Server) order(w http.ResponseWriter, r *http.Request, d, base, path string, a domain.Account, key app.PublicKey, payload []byte) {
	if s.orders == nil {
		s.problem(w, 503, "serverInternal")
		return
	}
	ref := app.AccountRef{Directory: d, ID: a.ID, Thumbprint: key.Thumbprint}
	if path == "new-order" {
		var in struct {
			Identifiers         []struct{ Type, Value string }
			NotBefore, NotAfter json.RawMessage
		}
		if json.Unmarshal(payload, &in) != nil || len(in.Identifiers) == 0 || len(in.Identifiers) > 100 {
			s.problem(w, 400, "malformed")
			return
		}
		if len(in.NotBefore) > 0 || len(in.NotAfter) > 0 {
			s.problem(w, 400, "malformed")
			return
		}
		names := make([]string, len(in.Identifiers))
		for i, id := range in.Identifiers {
			if id.Type != "dns" {
				s.problem(w, 400, "unsupportedIdentifier")
				return
			}
			names[i] = id.Value
		}
		o, e := s.orders.NewOrder(r.Context(), ref, names)
		if e != nil {
			s.fail(w, e)
			return
		}
		w.Header().Set("Location", base+"order/"+o.ID)
		s.json(w, 201, orderJSON(base, o))
		return
	}
	if path == "account/"+a.ID+"/orders" {
		if len(payload) != 0 {
			s.problem(w, 400, "malformed")
			return
		}
		after := r.URL.Query().Get("after")
		if len(after) > 43 {
			s.problem(w, 400, "malformed")
			return
		}
		ids, e := s.orders.Orders(r.Context(), ref, after)
		if e != nil {
			s.fail(w, e)
			return
		}
		urls := make([]string, 0, len(ids))
		for _, id := range ids {
			urls = append(urls, base+"order/"+id)
		}
		if len(ids) == 100 {
			w.Header().Add("Link", "<"+base+path+"?after="+ids[len(ids)-1]+">;rel=\"next\"")
		}
		s.json(w, 200, map[string]any{"orders": urls})
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 || len(parts[1]) != 43 {
		s.problem(w, 404, "malformed")
		return
	}
	id := parts[1]
	switch parts[0] {
	case "order":
		if len(parts) != 2 || len(payload) != 0 {
			s.problem(w, 400, "malformed")
			return
		}
		o, e := s.orders.Order(r.Context(), ref, id)
		if e != nil {
			s.fail(w, e)
			return
		}
		s.json(w, 200, orderJSON(base, o))
	case "authorization", "challenge":
		s.challenge(w, r, base, parts, ref, payload)
	case "finalize":
		if len(parts) != 2 {
			s.problem(w, 404, "malformed")
			return
		}
		s.finalize(w, r, base, id, ref, payload)
	case "certificate":
		if len(parts) != 2 || len(payload) != 0 {
			s.problem(w, 400, "malformed")
			return
		}
		c, e := s.orders.Certificate(r.Context(), ref, id)
		if e != nil {
			s.fail(w, e)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(200)
		_, _ = w.Write(c.Chain)
	default:
		s.problem(w, 404, "malformed")
	}
}
