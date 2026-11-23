package operations

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestManagementCanaryRequiresAuthenticationAndARealDisabledDraftWrite(t *testing.T) {
	writes := 0
	deny := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deny {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/auth/session":
			w.Write([]byte(`{"authenticated":true}`))
		case "/sites/11111111-1111-4111-8111-111111111111":
			w.Write([]byte(`{"name":"gatebeam-upgrade-canary-owned","revision":1,"draft":{"enabled":false}}`))
		case "/sites/11111111-1111-4111-8111-111111111111/draft":
			if r.Method != "PUT" || r.Header.Get("X-CSRF-Token") != "owned-csrf" {
				w.WriteHeader(403)
				return
			}
			var v map[string]any
			json.NewDecoder(r.Body).Decode(&v)
			if v["expected_revision"] != float64(1) {
				w.WriteHeader(409)
				return
			}
			writes++
			w.WriteHeader(200)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	spec := CanarySpec{SessionCookie: "owned-cookie", CSRFToken: "owned-csrf", SiteID: "11111111-1111-4111-8111-111111111111"}
	if e := VerifyManagementCanary(t.Context(), server.Client(), server.URL, "https://management.test", spec, true, strings.Repeat("a", 64)); e != nil || writes != 1 {
		t.Fatal("real read/write canary absent", writes, e)
	}
	deny = true
	if VerifyManagementCanary(t.Context(), server.Client(), server.URL, "https://management.test", spec, false, "") == nil {
		t.Fatal("401 mistaken for successful capability")
	}
}
