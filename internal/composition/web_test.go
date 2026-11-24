package composition

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestWebRoutesAndAssetBoundary(t *testing.T) {
	bundle := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>Gatebeam</title>")}, "assets/app.js": {Data: []byte("export{}")}}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) })
	handler := withWeb(api, bundle)
	for _, path := range []string{"/", "/login", "/enroll", "/recover", "/console/sites", "/console/targets", "/console/releases", "/console/certificates", "/console/credentials", "/console/overview", "/console/logs", "/console/alerts", "/console/backups", "/console/accounts", "/console/audit"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 200 || !strings.Contains(w.Body.String(), "Gatebeam") {
			t.Fatalf("SPA %s: %d", path, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("HTML cache boundary")
		}
	}
	for _, path := range []string{"/auth/session", "/accounts", "/unknown", "/sites", "/targets", "/releases", "/console/unknown", "/console/identities", "/console/sites/unknown", "/secrets/identity", "/assets/../index.html", "/assets/missing.js"} {
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code == 200 {
			t.Fatalf("unexpected SPA fallback: %s", path)
		}
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/assets/app.js", nil))
	if w.Code != 200 {
		t.Fatal("trusted asset unavailable")
	}
	w = httptest.NewRecorder()
	withWeb(api, fstest.MapFS{}).ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	body, _ := io.ReadAll(w.Result().Body)
	if w.Code != 503 || strings.Contains(string(body), "index.html") {
		t.Fatal("missing bundle must be explicit and path-safe")
	}
}
