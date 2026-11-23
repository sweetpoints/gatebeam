package httptransport

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUnimplementedStatusProtocolsNeverReturnSuccess(t *testing.T) {
	for _, path := range []string{"/ocsp", "/crl"} {
		w := httptest.NewRecorder()
		NewServer().ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s must explicitly report unavailable: %d", path, w.Code)
		}
	}
}
