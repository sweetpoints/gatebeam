//go:build integration

package multinode_test

import (
	"bytes"
	"context"
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	fixture "gatebeam/tests/fixtures/multinode"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestSchema22ExpandsBeforeDualNodeActivation(t *testing.T) {
	p := testkit.PostgresAt(t, 22)
	legacyBinary := os.Getenv("GATEBEAM_SCHEMA22_BINARY")
	bridgeBinary := os.Getenv("GATEBEAM_BRIDGE_BINARY")
	if legacyBinary == "" || bridgeBinary == "" {
		t.Fatal("build-schema22-fixture.sh required")
	}
	root := t.TempDir()
	identity := filepath.Join(root, "api.agekey")
	if e := secrets.EnsureIdentity(identity); e != nil {
		t.Fatal(e)
	}
	store, e := secrets.New(identity)
	if e != nil {
		t.Fatal(e)
	}
	ids := credential.New()
	uid, sid := uuid.NewString(), uuid.NewString()
	token, _ := ids.Random()
	csrf, _ := ids.Random()
	otp, e := totp.Generate(totp.GenerateOpts{Issuer: "historical22", AccountName: uid})
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := store.Seal("identity/totp/"+uid, []byte(otp.Secret()))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(t.Context(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,clock_timestamp()+interval '1 hour')`, sid, uid, ids.Digest(token), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	u, _ := url.Parse(os.Getenv("GATEBEAM_TEST_DATABASE_URL"))
	q := u.Query()
	q.Set("search_path", p.Config().ConnConfig.RuntimeParams["search_path"])
	u.RawQuery = q.Encode()
	database := filepath.Join(root, "database")
	if e = os.WriteFile(database, []byte(u.String()), 0600); e != nil {
		t.Fatal(e)
	}
	start := func(binary string) (string, func()) {
		listener, e := net.Listen("tcp", "127.0.0.1:0")
		if e != nil {
			t.Fatal(e)
		}
		address := listener.Addr().String()
		listener.Close()
		config := filepath.Join(root, filepath.Base(binary)+".json")
		body, _ := json.Marshal(map[string]any{"mode": "api", "environment": "development", "database_file": database, "identity_file": identity, "api_listen": address, "api_origin": "http://" + address})
		if e = os.WriteFile(config, body, 0600); e != nil {
			t.Fatal(e)
		}
		cmd := exec.CommandContext(t.Context(), binary, "--config", config)
		if e = cmd.Start(); e != nil {
			t.Fatal(e)
		}
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = cmd.Process.Signal(os.Interrupt)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(4 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
		}
		t.Cleanup(stop)
		end := time.Now().Add(5 * time.Second)
		for time.Now().Before(end) {
			request, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+address+"/sites", nil)
			request.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: token})
			r, e := http.DefaultClient.Do(request)
			if e == nil {
				r.Body.Close()
				if r.StatusCode == 200 {
					return address, stop
				}
			}
			time.Sleep(40 * time.Millisecond)
		}
		t.Fatal("historical/bridge API did not serve real identity and ingress SQL")
		return "", stop
	}
	writeSite := func(address, domain string) {
		body, _ := json.Marshal(map[string]any{"name": "old22 " + domain, "group_ids": []string{}, "config": map[string]any{"enabled": true, "domains": []string{domain}, "maintenance": map[string]any{"enabled": true, "status": 503, "message": "owned old22"}}})
		request, _ := http.NewRequestWithContext(t.Context(), "POST", "http://"+address+"/sites", bytes.NewReader(body))
		request.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: token})
		request.Header.Set("Origin", "http://"+address)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-CSRF-Token", csrf)
		r, e := http.DefaultClient.Do(request)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.StatusCode != 201 {
			t.Fatal("old22 write failed", r.StatusCode)
		}
	}
	oldAddress, stopOld := start(legacyBinary)
	writeSite(oldAddress, "before-expand.owned.test")
	if e = postgres.Migrate(t.Context(), p); e != nil {
		t.Fatal(e)
	}
	request, _ := http.NewRequestWithContext(t.Context(), "GET", "http://"+oldAddress+"/sites", nil)
	request.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: token})
	response, e := http.DefaultClient.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("schema expansion broke original executable", response.StatusCode)
	}
	writeSite(oldAddress, "after-expand.owned.test")
	stopOld()
	_, stopBridge := start(bridgeBinary)
	stopBridge()
	lab := fixture.StartMigrated(t, p, identity)
	for _, n := range lab.Nodes {
		if n.Configs["nginx"].RuntimeProtocol != 1 || n.Configs["management"].RuntimeProtocol != 1 {
			t.Fatal("activation before final protocol")
		}
		if _, e = p.Exec(t.Context(), `UPDATE identity_accounts SET last_step=-1 WHERE id=$1`, uid); e != nil {
			t.Fatal(e)
		}
		code, e := totp.GenerateCode(otp.Secret(), time.Now())
		if e != nil {
			t.Fatal(e)
		}
		body, _ := json.Marshal(map[string]any{"config": map[string]any{"names": []string{"historical.dual.test"}, "purpose": "serverAuth", "method": "import"}, "totp_code": code})
		status, raw := n.Request(t, "POST", "/certificates/spec", body, token, csrf)
		if status != 201 {
			t.Fatal("historical account MFA failed after controlled key rewrap", status, string(raw))
		}
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if exec.CommandContext(ctx, legacyBinary, "--runtime-contract").Run() == nil {
		t.Fatal("original22 executable accidentally approved as protocol1 rollback")
	}
	t.Log("actual pinned schema22 API executable read/write contract survives goose expand, current protocol-zero bridge API, original-holder TOTP rewrap to independent A/B, ten final protocol1 roles and controlled activation; raw22 rollback rejected")
}
