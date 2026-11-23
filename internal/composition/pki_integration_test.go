//go:build integration

package composition

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	authHTTP "gatebeam/internal/modules/identity/transport/http"
	pkiapp "gatebeam/internal/modules/pki/application"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"github.com/pquerna/otp/totp"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLivePKIManagementRequiresCurrentAdminFreshMFAAndCommitsBeforeSecret(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	apiKey := filepath.Join(t.TempDir(), "api.key")
	caKey := filepath.Join(t.TempDir(), "ca.key")
	for _, path := range []string{apiKey, caKey} {
		if e := secrets.EnsureIdentity(path); e != nil {
			t.Fatal(e)
		}
	}
	apiSecret, e := secrets.New(apiKey)
	if e != nil {
		t.Fatal(e)
	}
	caSecret, e := secrets.New(caKey)
	if e != nil {
		t.Fatal(e)
	}
	handler, e := newAPIHandlerWithPKI(p, apiSecret, nil, bootstrap.Config{CARecipient: caSecret.Recipient(), CAServerNames: []string{"host.example"}, CAClientNames: []string{"client.example"}}, authHTTP.Config{Origin: "http://localhost"})
	if e != nil {
		t.Fatal(e)
	}
	ids := credential.New()
	uid, _ := ids.NewID()
	sid, _ := ids.NewID()
	raw, _ := ids.Random()
	csrf, _ := ids.Random()
	seedKey, e := totp.Generate(totp.GenerateOpts{Issuer: "owned-test", AccountName: "admin"})
	if e != nil {
		t.Fatal(e)
	}
	seed := seedKey.Secret()
	cipher, e := apiSecret.Seal("identity/totp/"+uid, []byte(seed))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,now()+interval '1 hour')`, sid, uid, ids.Digest(raw), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	code := func() string {
		v, e := totp.GenerateCode(seed, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	request := func(path string, body any) *httptest.ResponseRecorder {
		b, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		r := httptest.NewRequest("POST", path, strings.NewReader(string(b)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://localhost")
		r.Header.Set("X-CSRF-Token", csrf)
		r.AddCookie(&http.Cookie{Name: "gatebeam-dev", Value: raw})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	spec := map[string]any{"names": []string{"host.example"}, "purpose": "serverAuth", "directory": "server", "expires": time.Now().Add(time.Hour)}
	if w := request("/pki/grants", spec); w.Code != 403 {
		t.Fatal("missing MFA accepted", w.Code)
	}
	spec["totp_code"] = code()
	w := request("/pki/grants", spec)
	if w.Code != 201 {
		t.Fatal("grant failed", w.Code)
	}
	var grant pkiapp.Grant
	if json.Unmarshal(w.Body.Bytes(), &grant) != nil || grant.ID == "" {
		t.Fatal("grant response")
	}
	var count int
	if e = p.QueryRow(ctx, "SELECT count(*) FROM pki_grants WHERE id=$1", grant.ID).Scan(&count); e != nil || count != 1 {
		t.Fatal("uncommitted success", e)
	}
	if w = request("/pki/grants/"+grant.ID+"/eab", map[string]string{"totp_code": code()}); w.Code != 403 {
		t.Fatal("same fresh proof reused", w.Code)
	}
	// Advance the owned fixture's proof watermark only; no wall-clock sleeps.
	if _, e = p.Exec(ctx, "UPDATE identity_accounts SET last_step=-1 WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	w = request("/pki/grants/"+grant.ID+"/eab", map[string]string{"totp_code": code()})
	if w.Code != 201 {
		t.Fatal("EAB failed", w.Code)
	}
	var binding pkiapp.EABCredentials
	if json.Unmarshal(w.Body.Bytes(), &binding) != nil || binding.HMAC == "" {
		t.Fatal("missing one-time secret")
	}
	var encrypted []byte
	if e = p.QueryRow(ctx, "SELECT cipher FROM pki_eab WHERE id=$1", binding.KeyID).Scan(&encrypted); e != nil {
		t.Fatal("EAB not committed", e)
	}
	if _, e = apiSecret.Open("pki/eab/"+binding.KeyID, encrypted); e == nil {
		t.Fatal("API opened EAB")
	}
	if _, e = caSecret.Open("pki/eab/"+binding.KeyID, encrypted); e != nil {
		t.Fatal("CA cannot open EAB", e)
	}
	var auditBody string
	if e = p.QueryRow(ctx, "SELECT string_agg(payload::text,'') FROM audit").Scan(&auditBody); e != nil {
		t.Fatal(e)
	}
	for _, secret := range []string{binding.HMAC, seed, raw, csrf, code()} {
		if strings.Contains(auditBody, secret) {
			t.Fatal("secret in audit")
		}
	}
	// P4 exercises the live API through the same fresh-MFA binding. DER is
	// metadata-only here; cryptographic issuance/status is covered in PKI tests.
	for _, q := range []string{
		"INSERT INTO pki_issuers(id,fingerprint,certificate_der,not_before,not_after) VALUES('status-issuer','status-issuer','public',now(),now()+interval '1 hour')",
		"INSERT INTO pki_serial_reservations(issuer_id,serial) VALUES('status-issuer','0000000000000000000000000000000000000001')",
	} {
		if _, e = p.Exec(ctx, q); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = p.Exec(ctx, "INSERT INTO pki_accounts(id,principal_id,directory,thumbprint,public_key,status,contacts) VALUES('status-account',$1,'server','status-thumb','public','valid','{}')", grant.Principal.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "INSERT INTO pki_orders(id,account_id,directory,names,purpose,status,expires,challenges,revision) VALUES('status-order','status-account','server',ARRAY['host.example'],'serverAuth','valid',now()+interval '1 hour','[]',1)"); e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, "INSERT INTO pki_certificates(order_id,issuer_id,serial,der,chain,not_before,not_after) VALUES('status-order','status-issuer','0000000000000000000000000000000000000001','public','public',now(),now()+interval '1 hour')"); e != nil {
		t.Fatal(e)
	}
	revokePath := "/pki/issuers/status-issuer/certificates/0000000000000000000000000000000000000001/revoke"
	if w = request(revokePath, map[string]any{"reason": 1, "totp_code": code()}); w.Code != 403 {
		t.Fatal("revocation reused MFA", w.Code)
	}
	if _, e = p.Exec(ctx, "UPDATE identity_accounts SET last_step=-1 WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	if w = request(revokePath, map[string]any{"reason": 1, "totp_code": code()}); w.Code != 204 {
		t.Fatal("revocation API failed", w.Code)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM pki_revocations WHERE issuer_id='status-issuer'").Scan(&count); e != nil || count != 1 {
		t.Fatal("revocation returned before commit", e, count)
	}
	if e = p.QueryRow(ctx, "SELECT count(*) FROM audit WHERE action='pki.certificate.revoked'").Scan(&count); e != nil || count != 1 {
		t.Fatal("revocation missing audit", e, count)
	}
	if _, e = p.Exec(ctx, "UPDATE identity_accounts SET last_step=-1 WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	if w = request("/pki/principals/"+grant.Principal.ID+"/disable", map[string]string{"totp_code": code()}); w.Code != 204 {
		t.Fatal("disable failed", w.Code)
	}
	var disabled bool
	if e = p.QueryRow(ctx, "SELECT disabled FROM pki_principals WHERE id=$1", grant.Principal.ID).Scan(&disabled); e != nil || !disabled {
		t.Fatal("disable returned before commit", e)
	}
	if _, e = p.Exec(ctx, "UPDATE identity_accounts SET role='readonly',last_step=-1 WHERE id=$1", uid); e != nil {
		t.Fatal(e)
	}
	if w = request("/pki/grants/"+grant.ID+"/eab", map[string]string{"totp_code": code()}); w.Code != 403 {
		t.Fatal("demoted current actor authorized", w.Code)
	}
	if w = request(revokePath, map[string]any{"reason": 1, "totp_code": code()}); w.Code != 403 {
		t.Fatal("demoted actor revoked", w.Code)
	}
}

func TestComposedPKIRejectsAPIAgeRecipient(t *testing.T) {
	p := testkit.Postgres(t)
	path := filepath.Join(t.TempDir(), "api.key")
	if e := secrets.EnsureIdentity(path); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = newAPIHandlerWithPKI(p, se, nil, bootstrap.Config{CARecipient: se.Recipient(), CAServerNames: []string{"host.example"}, CAClientNames: []string{"client.example"}}, authHTTP.Config{Origin: "http://localhost"}); e == nil {
		t.Fatal("API identity reused as CA EAB recipient")
	}
}
