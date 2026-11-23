package acme

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBootstrapDoesNotRequireExistingLeafMTLS(t *testing.T) {
	s := httptest.NewUnstartedServer(NewServer())
	s.TLS = TLSConfig()
	s.StartTLS()
	defer s.Close()
	if s.TLS.ClientAuth != tls.NoClientCert {
		t.Fatal("bootstrap requires leaf certificate")
	}
	for _, path := range []string{"/acme/server/directory", "/acme/client/directory", "/acme/server/new-account", "/acme/client/new-order"} {
		req, e := http.NewRequest(http.MethodGet, s.URL+path, nil)
		if e != nil {
			t.Fatal(e)
		}
		resp, e := s.Client().Do(req)
		if e != nil {
			t.Fatal(e)
		}
		var p struct {
			Type   string
			Status int
		}
		e = json.NewDecoder(resp.Body).Decode(&p)
		resp.Body.Close()
		if e != nil || resp.StatusCode != 503 || p.Type != "urn:ietf:params:acme:error:serverInternal" || p.Status != 503 {
			t.Fatalf("expected explicit protocol unavailability: %s %v", path, e)
		}
	}
	resp, e := s.Client().Get(s.URL + "/issue")
	if e != nil {
		t.Fatal(e)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("private issuance route exists")
	}
}
