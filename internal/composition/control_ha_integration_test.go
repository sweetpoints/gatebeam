//go:build integration

package composition

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/lifecycle"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRoleReadinessIsIndependent(t *testing.T) {
	state := lifecycle.New(time.Now)
	state.SetReady(lifecycle.Data, true)
	state.SetReady(lifecycle.Management, true)
	state.SetReady(lifecycle.ACME, true)
	state.SetReady(lifecycle.Status, true)
	state.SetReady(lifecycle.Query, true)
	temp, e := os.MkdirTemp("", "gatebeam-health-")
	if e != nil {
		t.Fatal(e)
	}
	defer os.RemoveAll(temp)
	parent, e := filepath.EvalSymlinks(temp)
	if e != nil {
		t.Fatal(e)
	}
	socket := filepath.Join(parent, "control.sock")
	health, e := startRoleHealth(t.Context(), bootstrap.Config{HealthListen: "127.0.0.1:0", ControlSocket: socket, DrainSeconds: 1}, state)
	if e != nil {
		t.Fatal(e)
	}
	defer health.Close()
	check := func(path string, want int) {
		t.Helper()
		r, e := http.Get("http://" + health.Address + path)
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("%s status=%d body=%s", path, r.StatusCode, body)
		}
		if strings.Contains(string(body), "postgres") || strings.Contains(string(body), "secret") {
			t.Fatal("probe exposed credentials")
		}
	}
	state.SetReady(lifecycle.Query, false)
	state.SetReady(lifecycle.Management, false)
	state.SetReady(lifecycle.ACME, false)
	check("/readyz/query", 503)
	check("/readyz/acme", 503)
	check("/readyz/status", 200)
	check("/readyz/data", 200)
	check("/livez", 200)
	// The private probe listener exposes no mutating maintenance route.
	r, e := http.Post("http://"+health.Address+"/drain", "application/json", strings.NewReader("{}"))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 404 {
		t.Fatal("network probe listener controls maintenance")
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	r, e = client.Post("http://deployment/drain", "application/json", strings.NewReader("{}"))
	if e != nil {
		t.Fatal(e)
	}
	r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatal("controlled drain rejected", r.StatusCode)
	}
	check("/readyz/data", 503)
	check("/livez", 200)
}

func TestManagementPeersShareSessionAndRecheckRevocation(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	files := []string{filepath.Join(t.TempDir(), "api-a"), filepath.Join(t.TempDir(), "api-b"), filepath.Join(t.TempDir(), "provider"), filepath.Join(t.TempDir(), "leaf")}
	keys := make([]*secrets.Store, len(files))
	for i, file := range files {
		if e := secrets.EnsureIdentity(file); e != nil {
			t.Fatal(e)
		}
		var e error
		keys[i], e = secrets.New(file)
		if e != nil {
			t.Fatal(e)
		}
	}
	public := []string{keys[0].Recipient(), keys[1].Recipient()}
	for i := 0; i < 2; i++ {
		var e error
		keys[i], e = secrets.NewRoleStore(files[i], public)
		if e != nil {
			t.Fatal(e)
		}
	}
	cfg := bootstrap.Config{CertificateProviderRecipient: keys[2].Recipient(), CertificateRecipient: keys[3].Recipient()}
	peer, e := pgxpool.NewWithConfig(ctx, p.Config().Copy())
	if e != nil {
		t.Fatal(e)
	}
	defer peer.Close()
	handlers := []http.Handler{}
	for i, pool := range []*pgxpool.Pool{p, peer} {
		h, e := newAPIHandlerWithPKI(pool, keys[i], nil, cfg, authHTTP.Config{Origin: "http://localhost"})
		if e != nil {
			t.Fatal(e)
		}
		handlers = append(handlers, h)
	}
	ids := credential.New()
	uid, _ := ids.NewID()
	sid, _ := ids.NewID()
	raw, _ := ids.Random()
	csrf, _ := ids.Random()
	totpKey, e := totp.Generate(totp.GenerateOpts{Issuer: "owned", AccountName: "replica"})
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := keys[0].Seal("identity/totp/"+uid, []byte(totpKey.Secret()))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,clock_timestamp()+interval '1 hour')`, sid, uid, ids.Digest(raw), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	request := func(index int, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: raw})
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://localhost")
		r.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		handlers[index].ServeHTTP(w, r)
		return w
	}
	for i := 0; i < 2; i++ {
		if w := request(i, "GET", "/runtime/status", ""); w.Code != 200 {
			t.Fatal("shared session rejected", i, w.Code, w.Body.String())
		}
	}
	code, e := totp.GenerateCode(totpKey.Secret(), time.Now())
	if e != nil {
		t.Fatal(e)
	}
	body := `{"config":{"zone_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","zone_name":"owned.test"},"secret":"owned-provider-token","totp_code":"` + code + `"}`
	if w := request(1, "POST", "/certificates/credential", body); w.Code != 201 {
		t.Fatal("B could not use A encrypted TOTP and session", w.Code, w.Body.String())
	}
	if _, e = p.Exec(ctx, `UPDATE identity_sessions SET revoked=true WHERE id=$1`, sid); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 2; i++ {
		if w := request(i, "GET", "/runtime/status", ""); w.Code != 401 {
			t.Fatal("replica cached revoked session", i, w.Code)
		}
	}
}

func TestManagedRoleDependencyOutageStaysLive(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	cfg := p.Config().Copy()
	relay := newRelay(t, net.JoinHostPort(cfg.ConnConfig.Host, fmt.Sprint(cfg.ConnConfig.Port)))
	relay.setDown(true)
	dsn, e := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	if e != nil {
		t.Fatal(e)
	}
	dsn.Host = relay.Addr().String()
	parameters := dsn.Query()
	parameters.Set("search_path", cfg.ConnConfig.RuntimeParams["search_path"])
	dsn.RawQuery = parameters.Encode()
	dir := t.TempDir()
	database, identity := filepath.Join(dir, "db"), filepath.Join(dir, "identity")
	if e := os.WriteFile(database, []byte(dsn.String()), 0600); e != nil {
		t.Fatal(e)
	}
	if e := secrets.EnsureIdentity(identity); e != nil {
		t.Fatal(e)
	}
	reserve := func() string {
		t.Helper()
		l, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := l.Addr().String()
		l.Close()
		return address
	}
	apiAddress, healthAddress := reserve(), reserve()
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(runCtx, "api", bootstrap.Config{Mode: "api", Environment: "development", IdentityFile: identity, DatabaseFile: database, APIListen: apiAddress, APIOrigin: "http://" + apiAddress, HealthListen: healthAddress, DrainSeconds: 1})
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case e := <-done:
			if e != nil {
				t.Error(e)
			}
		case <-time.After(3 * time.Second):
			t.Error("managed role exceeded drain deadline")
		}
	})
	client := &http.Client{Timeout: 300 * time.Millisecond}
	wait := func(path string, status int) {
		t.Helper()
		deadline := time.NewTimer(8 * time.Second)
		defer deadline.Stop()
		tick := time.NewTicker(30 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case e := <-done:
				t.Fatalf("dependency outage exited process: %v", e)
			case <-deadline.C:
				t.Fatalf("probe %s did not become %d", path, status)
			case <-tick.C:
				r, e := client.Get("http://" + healthAddress + path)
				if e == nil {
					r.Body.Close()
					if r.StatusCode == status {
						return
					}
				}
			}
		}
	}
	wait("/livez", 200)
	wait("/readyz/management", 503)
	select {
	case e := <-done:
		t.Fatalf("outage forced restart: %v", e)
	case <-time.After(1100 * time.Millisecond):
	}
	relay.setDown(false)
	wait("/readyz/management", 200)
	_ = ctx
}

func TestDrainUsesTheBoundedOperatorDeadline(t *testing.T) {
	s := lifecycle.New(time.Now)
	deadline := time.Now().Add(2 * time.Second).UTC()
	raw, _ := json.Marshal(map[string]any{"deadline": deadline})
	request := httptest.NewRequest("POST", "/drain", bytes.NewReader(raw))
	response := httptest.NewRecorder()
	controlHandler(bootstrap.Config{DrainSeconds: 60}, s).ServeHTTP(response, request)
	if response.Code != 200 || !s.Snapshot().Deadline.Equal(deadline) {
		t.Fatal("operator deadline ignored", response.Code, s.Snapshot().Deadline)
	}
	bad, _ := json.Marshal(map[string]any{"deadline": time.Now().Add(time.Hour)})
	response = httptest.NewRecorder()
	controlHandler(bootstrap.Config{}, lifecycle.New(time.Now)).ServeHTTP(response, httptest.NewRequest("POST", "/drain", bytes.NewReader(bad)))
	if response.Code != 400 {
		t.Fatal("unbounded operator drain accepted")
	}
}
