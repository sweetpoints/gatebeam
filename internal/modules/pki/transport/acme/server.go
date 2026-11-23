// Package acme implements the RFC8555 HTTP and JSON wire boundary.
package acme

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/pki/application/acme"
	statusapp "gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/modules/pki/domain"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

type Accounts interface {
	Lookup(context.Context, string, string, string) (domain.Account, error)
	Register(context.Context, app.Registration) (domain.Account, bool, error)
	Current(context.Context, string, string, string, []string, bool) (domain.Account, error)
	ChangeKey(context.Context, string, string, string, app.PublicKey) (domain.Account, error)
}
type Nonces interface {
	Issue(context.Context) (string, error)
	Consume(context.Context, string) error
}
type Server struct {
	origin      string
	accounts    Accounts
	nonces      Nonces
	crypto      app.Crypto
	orders      Orders
	revocations Revocations
}

// NewServer retains the unavailable bootstrap handler when no protocol services
// are configured; NewProtocol is the actual CA process assembly.
func NewServer() *Server { return &Server{} }
func NewProtocol(origin string, accounts Accounts, nonces Nonces, crypto app.Crypto, orders ...Orders) (*Server, error) {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || accounts == nil || nonces == nil || crypto == nil {
		return nil, errMalformed
	}
	s := &Server{origin: origin, accounts: accounts, nonces: nonces, crypto: crypto}
	if len(orders) > 0 {
		s.orders = orders[0]
	}
	return s, nil
}
func TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.NoClientCert}
}
func (s *Server) problem(w http.ResponseWriter, status int, kind string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	problem := map[string]any{"type": "urn:ietf:params:acme:error:" + kind, "status": status, "detail": kind}
	if kind == "unsupportedContact" {
		problem["detail"] = "unsupported contact scheme; supported scheme: mailto"
	}
	if kind == "badSignatureAlgorithm" {
		problem["algorithms"] = []string{"RS256", "ES256", "ES384"}
	}
	_ = json.NewEncoder(w).Encode(problem)
}
func (s *Server) fail(w http.ResponseWriter, e error) {
	switch {
	case errors.Is(e, domain.ErrAccountDeactivated):
		s.problem(w, 401, "unauthorized")
	case errors.Is(e, domain.ErrAlreadyRevoked):
		s.problem(w, 400, "alreadyRevoked")
	case errors.Is(e, domain.ErrRevocationReason):
		s.problem(w, 400, "badRevocationReason")
	case errors.Is(e, statusapp.ErrDenied):
		s.problem(w, 403, "unauthorized")
	case errors.Is(e, app.ErrOrderNotReady):
		s.problem(w, 403, "orderNotReady")
	case errors.Is(e, app.ErrBadCSR):
		s.problem(w, 400, "badCSR")
	case errors.Is(e, app.ErrOrderNotFound):
		s.problem(w, 404, "malformed")
	case errors.Is(e, app.ErrBadNonce):
		s.problem(w, 400, "badNonce")
	case errors.Is(e, app.ErrNotFound):
		s.problem(w, 400, "accountDoesNotExist")
	case errors.Is(e, app.ErrEABRequired):
		s.problem(w, 400, "externalAccountRequired")
	case errors.Is(e, app.ErrDenied), errors.Is(e, domain.ErrPolicy):
		s.problem(w, 403, "unauthorized")
	case errors.Is(e, app.ErrConflict):
		s.problem(w, 409, "malformed")
	case errors.Is(e, errMalformed):
		s.problem(w, 400, "malformed")
	default:
		s.problem(w, 503, "serverInternal")
	}
}
func (s *Server) json(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "acme" || (parts[1] != "server" && parts[1] != "client") {
		http.NotFound(w, r)
		return
	}
	if s.accounts == nil {
		s.problem(w, 503, "serverInternal")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	d := parts[1]
	base := s.origin + "/acme/" + d + "/"
	path := strings.Join(parts[2:], "/")
	w.Header().Set("Link", "<"+base+"directory>;rel=\"index\"")
	if path == "directory" && (r.Method == "GET" || r.Method == "HEAD") {
		if r.Method == "HEAD" {
			w.WriteHeader(200)
			return
		}
		s.directory(w, base)
		return
	}
	if path == "new-nonce" && (r.Method == "HEAD" || r.Method == "GET") {
		if !s.fresh(w, r) {
			return
		}
		if r.Method == "HEAD" {
			w.WriteHeader(200)
		} else {
			w.WriteHeader(204)
		}
		return
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		s.problem(w, 405, "malformed")
		return
	}
	if !s.fresh(w, r) {
		return
	}
	media, _, e := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if e != nil || media != "application/jose+json" {
		s.problem(w, 415, "malformed")
		return
	}
	raw, e := io.ReadAll(http.MaxBytesReader(w, r.Body, 65536))
	if e != nil {
		s.problem(w, 400, "malformed")
		return
	}
	env, e := parseEnvelope(raw, true)
	if e != nil {
		s.fail(w, e)
		return
	}
	h := env.header
	if h.Algorithm != "RS256" && h.Algorithm != "ES256" && h.Algorithm != "ES384" {
		s.problem(w, 400, "badSignatureAlgorithm")
		return
	}
	var key app.PublicKey
	var account domain.Account
	if path == "new-account" || (path == "revoke-cert" && len(h.Key) > 0) {
		if len(h.Key) == 0 {
			s.problem(w, 400, "malformed")
			return
		}
		key, e = s.crypto.PublicKey(h.Key)
	} else {
		prefix := base + "account/"
		if !strings.HasPrefix(h.KeyID, prefix) || strings.Contains(strings.TrimPrefix(h.KeyID, prefix), "/") {
			s.problem(w, 400, "malformed")
			return
		}
		account, e = s.accounts.Lookup(r.Context(), d, strings.TrimPrefix(h.KeyID, prefix), "")
		if e == nil {
			key, e = s.crypto.PublicKey(account.Key)
		}
	}
	if e != nil {
		if errors.Is(e, app.ErrNotFound) {
			s.fail(w, e)
		} else {
			s.problem(w, 400, "badPublicKey")
		}
		return
	}
	payload, e := s.crypto.Verify(raw, key.Encoded, false)
	if e != nil {
		s.problem(w, 400, "malformed")
		return
	}
	// Independent commit BEFORE URL, payload, EAB or account business validation.
	if e = s.nonces.Consume(r.Context(), h.Nonce); e != nil {
		s.fail(w, e)
		return
	}
	if h.URL != s.origin+r.URL.RequestURI() || r.Host != strings.TrimPrefix(s.origin, "https://") {
		s.problem(w, 403, "unauthorized")
		return
	}
	// Only after signature, nonce and canonical URL validation: every request
	// from an already-deactivated account has the RFC8555 section7.3.6 wire
	// response. Application final checks still detect concurrent deactivation.
	if account.Status == "deactivated" {
		s.problem(w, 401, "unauthorized")
		return
	}
	switch {
	case path == "directory" || path == "new-nonce":
		if len(payload) != 0 {
			s.problem(w, 400, "malformed")
			return
		}
		if _, e = s.accounts.Current(r.Context(), d, account.ID, key.Thumbprint, nil, false); e != nil {
			s.fail(w, e)
			return
		}
		if path == "directory" {
			s.directory(w, base)
		} else {
			w.WriteHeader(204)
		}
	case path == "new-account":
		s.register(w, r, d, base, key, payload)
	case path == "revoke-cert":
		s.revoke(w, r, d, account, key, payload)
	case path == "key-change":
		s.rollover(w, r, d, base, account, key, payload)
	case path == "account/"+account.ID:
		s.account(w, r, d, base, account, key, payload)
	case path == "new-order" || strings.HasPrefix(path, "order/") || strings.HasPrefix(path, "authorization/") || strings.HasPrefix(path, "challenge/") || strings.HasPrefix(path, "finalize/") || strings.HasPrefix(path, "certificate/") || path == "account/"+account.ID+"/orders":
		s.order(w, r, d, base, path, account, key, payload)
	default:
		if _, e = s.accounts.Current(r.Context(), d, account.ID, key.Thumbprint, nil, false); e != nil {
			s.fail(w, e)
			return
		}
		s.problem(w, 503, "serverInternal")
	}
}

func (s *Server) directory(w http.ResponseWriter, base string) {
	s.json(w, 200, map[string]any{"newNonce": base + "new-nonce", "newAccount": base + "new-account", "newOrder": base + "new-order", "revokeCert": base + "revoke-cert", "keyChange": base + "key-change", "meta": map[string]bool{"externalAccountRequired": true}})
}
