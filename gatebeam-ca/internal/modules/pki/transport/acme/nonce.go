package acme

import "net/http"

func (s *Server) fresh(w http.ResponseWriter, r *http.Request) bool {
	n, e := s.nonces.Issue(r.Context())
	if e != nil {
		s.fail(w, e)
		return false
	}
	w.Header().Set("Replay-Nonce", n)
	return true
}
