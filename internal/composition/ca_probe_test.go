package composition

import (
	"gatebeam/internal/platform/lifecycle"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPrivateCAEntryRequiresBothProtocolCapabilities(t *testing.T) {
	state := lifecycle.New(time.Now)
	handler := healthHandler(state)
	check := func(want int) {
		t.Helper()
		r := httptest.NewRecorder()
		handler.ServeHTTP(r, httptest.NewRequest("GET", "/readyz/ca", nil))
		if r.Code != want {
			t.Fatal("private CA entry readiness", r.Code, want)
		}
	}
	state.SetReady(lifecycle.ACME, true)
	state.SetReady(lifecycle.Status, false)
	check(503)
	state.SetReady(lifecycle.Status, true)
	check(200)
	state.SetReady(lifecycle.ACME, false)
	check(503)
}
