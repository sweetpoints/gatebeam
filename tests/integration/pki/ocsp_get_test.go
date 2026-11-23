//go:build integration

package pki_test

import (
	"bytes"
	"crypto"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ocsp"
)

func TestOCSPGETPreservesBase64Slashes(t *testing.T) {
	request := ocsp.Request{
		HashAlgorithm:  crypto.SHA1,
		IssuerNameHash: bytes.Repeat([]byte{0xff}, 20),
		IssuerKeyHash:  make([]byte, 20),
		SerialNumber:   big.NewInt(1),
	}
	der, err := request.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(der)
	if !strings.Contains(encoded, "//") {
		t.Fatal("test request does not exercise adjacent slashes")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/ocsp/", func(w http.ResponseWriter, r *http.Request) {
		if got := strings.TrimPrefix(r.URL.Path, "/ocsp/"); got != encoded {
			t.Errorf("mux changed the OCSP payload: got %q, want %q", got, encoded)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, ocspGETURL("http://ca.test", der), nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("OCSP request did not reach the handler: HTTP %d, Location %q", response.Code, response.Header().Get("Location"))
	}
}
