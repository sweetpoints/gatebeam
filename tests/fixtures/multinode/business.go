//go:build integration

package multinode

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	pkidomain "gatebeam/internal/modules/pki/domain"
	"gatebeam/internal/platform/bootstrap"
	"gatebeam/internal/platform/secrets"
	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

type Session struct {
	Cookie, CSRF, UserID, Secret string
	Lab                          *Lab
}

func (l *Lab) Session(t testing.TB) *Session {
	t.Helper()
	ids := credential.New()
	uid, sid := uuid.NewString(), uuid.NewString()
	cookie, e := ids.Random()
	if e != nil {
		t.Fatal(e)
	}
	csrf, e := ids.Random()
	if e != nil {
		t.Fatal(e)
	}
	var pubs []string
	for _, n := range l.Nodes {
		key, e := secrets.New(filepath.Join(n.Secrets["management"], "identity.agekey"))
		if e != nil {
			t.Fatal(e)
		}
		pubs = append(pubs, key.Recipient())
	}
	store, e := secrets.NewRoleStore(filepath.Join(l.Nodes[0].Secrets["management"], "identity.agekey"), pubs)
	if e != nil {
		t.Fatal(e)
	}
	otp, e := totp.Generate(totp.GenerateOpts{Issuer: "owned-multinode", AccountName: uid})
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := store.Seal("identity/totp/"+uid, []byte(otp.Secret()))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = l.Pool.Exec(t.Context(), `INSERT INTO identity_accounts(id,name,state,auth_version,last_step,seed,invite_expires,locked_until,role) VALUES($1,$1,'active',1,-1,$2,'0001-01-01','0001-01-01','admin')`, uid, cipher); e != nil {
		t.Fatal(e)
	}
	if _, e = l.Pool.Exec(t.Context(), `INSERT INTO identity_sessions(id,account_id,token_hash,csrf_hash,auth_version,expires) VALUES($1,$2,$3,$4,1,clock_timestamp()+interval '1 hour')`, sid, uid, ids.Digest(cookie), ids.Digest(csrf)); e != nil {
		t.Fatal(e)
	}
	return &Session{Cookie: cookie, CSRF: csrf, UserID: uid, Secret: otp.Secret(), Lab: l}
}
func (s *Session) MFA(t testing.TB) string {
	t.Helper()
	if _, e := s.Lab.Pool.Exec(t.Context(), `UPDATE identity_accounts SET last_step=-1 WHERE id=$1`, s.UserID); e != nil {
		t.Fatal(e)
	}
	code, e := totp.GenerateCode(s.Secret, time.Now())
	if e != nil {
		t.Fatal(e)
	}
	return code
}
func (s *Session) Call(t testing.TB, method, path string, body any, want int) []byte {
	t.Helper()
	return s.call(t, method, path, body, want, false)
}
func (s *Session) prepareCall(t testing.TB, method, path string, body any, want int) []byte {
	t.Helper()
	return s.call(t, method, path, body, want, true)
}
func (s *Session) call(t testing.TB, method, path string, body any, want int, prepare bool) []byte {
	t.Helper()
	var raw []byte
	var e error
	if body != nil {
		raw, e = json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
	}
	request := s.Lab.Nodes[0].Request
	if prepare {
		request = s.Lab.Nodes[0].prepareRequest
	}
	code, out := request(t, method, path, raw, s.Cookie, s.CSRF)
	if code != want {
		n := s.Lab.Nodes[0]
		t.Logf("unexpected owned API response: method=%s path=%s status=%d", method, path, code)
		if code == http.StatusServiceUnavailable {
			s.Lab.LogManagementReadiness(t)
		}
		t.Log("native management log", n.Compose(t, "logs", "--tail", "16", "management"))
		t.Log("native entry log", n.Compose(t, "logs", "--tail", "16", "nginx"))
		t.Fatalf("owned business API %s %s: %d %s", method, path, code, out)
	}
	return out
}

type Business struct {
	SiteID, TargetID, CertificateID string
	Trust                           []byte
	Clients                         map[string]*http.Client
	Lab                             *Lab
	Session                         *Session
}

func (b *Business) Get(t testing.TB, n *Node, path string) int {
	t.Helper()
	r, e := b.Clients[n.Info.Node.ID].Get("https://service.dual.test" + path)
	if e != nil {
		t.Log("native state at failed new connection", n.Info.Node.ID, n.Health(t, "nginx"))
		t.Log("native control log", n.Compose(t, "logs", "--tail", "16", "nginx"))
		t.Log("confirmed native baseline", string(n.Admin(t, "inspect-boot")))
		t.Fatal("actual business TLS failed", e)
	}
	body, readErr := io.ReadAll(io.LimitReader(r.Body, 1024))
	r.Body.Close()
	if readErr != nil || r.StatusCode == 200 && string(body) != "owned-business" {
		t.Fatal("business response body unavailable or mismatched", readErr)
	}
	return r.StatusCode
}
func (l *Lab) Business(t testing.TB) *Business {
	t.Helper()
	if l.BusinessInstance != nil {
		return l.BusinessInstance
	}
	b := &Business{Lab: l, Session: l.Session(t), Clients: map[string]*http.Client{}}
	s := b.Session
	rootKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().Add(-time.Minute)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "owned external fixture root"}, NotBefore: now, NotAfter: now.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	root, e = x509.ParseCertificate(rootDER)
	if e != nil {
		t.Fatal(e)
	}
	b.Trust = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), DNSNames: []string{"service.dual.test"}, NotBefore: now, NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, leaf, root, &key.PublicKey, rootKey)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(private)
	cert := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), b.Trust...)
	var resource struct{ ID string }
	raw := s.prepareCall(t, "POST", "/certificates/spec", map[string]any{"config": map[string]any{"names": []string{"service.dual.test"}, "purpose": "serverAuth", "method": "import"}, "totp_code": s.MFA(t)}, 201)
	if json.Unmarshal(raw, &resource) != nil || resource.ID == "" {
		t.Fatal("missing certificate resource")
	}
	b.CertificateID = resource.ID
	s.prepareCall(t, "POST", "/certificates/spec/"+resource.ID+"/import", map[string]any{"certificate_pem": string(cert), "private_key_pem": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})), "totp_code": s.MFA(t)}, 201)
	name := l.Run + "-business"
	probe := os.Getenv("GATEBEAM_COMPOSE_PROBE_BINARY")
	Docker(t, "run", "-d", "--name", name, "--label", "gatebeam.fixture.run="+l.Run, "--network", l.Network, "--ip", "10.254.248.50", "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "64m", "--cpus", "0.5", "--pids-limit", "64", "-v", probe+":/capabilities:ro", "-e", "GATEBEAM_TEST_BACKEND=1", "--entrypoint", "/capabilities", "gatebeam-edge:local")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), cleanupBudget(10*time.Second))
		defer cancel()
		_ = exec.CommandContext(ctx, "docker", "rm", "-f", name).Run()
	})
	var target struct {
		ResourceID string `json:"resource_id"`
	}
	raw = s.prepareCall(t, "POST", "/targets", map[string]any{"config": map[string]any{"name": "owned private business", "protocol": "http", "members": []map[string]any{{"address": "10.254.248.50", "port": 8080, "weight": 1}}, "allowed_networks": []string{"10.254.248.0/24"}}}, 201)
	if json.Unmarshal(raw, &target) != nil || target.ResourceID == "" {
		t.Fatal("missing target", string(raw))
	}
	b.TargetID = target.ResourceID
	var site struct {
		ResourceID string `json:"resource_id"`
	}
	raw = s.prepareCall(t, "POST", "/sites", map[string]any{"name": "owned public business", "group_ids": []string{}, "config": map[string]any{"enabled": true, "domains": []string{"service.dual.test"}, "default_target": map[string]string{"id": b.TargetID}, "connection": map[string]any{"connect_timeout_seconds": 1, "read_timeout_seconds": 2, "send_timeout_seconds": 2, "max_body_bytes": 1048576, "websocket": true, "sse": true, "buffer_responses": false}, "entry_certificate": map[string]any{"id": b.CertificateID, "revision": 1, "status": "unavailable"}}}, 201)
	if json.Unmarshal(raw, &site) != nil || site.ResourceID == "" {
		t.Fatal("missing site", string(raw))
	}
	b.SiteID = site.ResourceID
	var candidate struct{ ID string }
	raw = s.prepareCall(t, "POST", "/releases/prepare", map[string]any{"site_ids": []string{b.SiteID}, "expected": map[string]int64{"site:" + b.SiteID: 1, "target:" + b.TargetID: 1}}, 201)
	if json.Unmarshal(raw, &candidate) != nil || candidate.ID == "" {
		t.Fatal("missing candidate", string(raw))
	}
	s.prepareCall(t, "POST", "/releases/"+candidate.ID+"/publish", struct{}{}, 202)
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(b.Trust)
	for _, n := range l.Nodes {
		address := n.Port(t, 443)
		b.Clients[n.Info.Node.ID] = &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "service.dual.test", MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, address)
		}}}
	}
	// This waits for asynchronous initial fixture creation before fault injection.
	// Keep each owner's production Apply/route deadlines and each real TLS
	// request unchanged; only the aggregate software preparation guard scales.
	started := time.Now()
	budget := cleanupBudget(10 * time.Second)
	deadline := started.Add(budget)
	preparation, cancel := context.WithDeadline(t.Context(), deadline)
	defer cancel()
	var releaseState string
	var confirmedNodes int
	statuses := make(map[string]int, len(l.Nodes))
	for preparation.Err() == nil && time.Now().Before(deadline) {
		// A canary request can pass before the authority transaction commits.
		// Fault injection starts only after both native confirmations and the
		// cluster release receipt, never from a transient candidate load.
		if err := l.Pool.QueryRow(preparation, `SELECT state,(SELECT count(*) FROM deployment_node_runtime WHERE release_id=$1 AND body->>'state'='succeeded') FROM deployment_releases WHERE id=$1`, candidate.ID).Scan(&releaseState, &confirmedNodes); err != nil {
			if preparation.Err() != nil {
				break
			}
			t.Fatal(err)
		}
		if releaseState != "succeeded" || confirmedNodes != 2 {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		ok := true
		for _, n := range l.Nodes {
			request, e := http.NewRequestWithContext(preparation, "GET", "https://service.dual.test/", nil)
			if e != nil {
				t.Fatal(e)
			}
			r, e := b.Clients[n.Info.Node.ID].Do(request)
			if e != nil {
				statuses[n.Info.Node.ID] = 0
				ok = false
			} else {
				statuses[n.Info.Node.ID] = r.StatusCode
				r.Body.Close()
				if r.StatusCode != 200 {
					ok = false
				}
			}
		}
		if ok && preparation.Err() == nil && time.Now().Before(deadline) {
			t.Logf("initial business publication confirmed: elapsed=%s budget=%s confirmed_nodes=%d", time.Since(started), budget, confirmedNodes)
			l.BusinessInstance = b
			return b
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("initial business publication observation: elapsed=%s budget=%s state=%s confirmed_nodes=%d node_http_status=%v", time.Since(started), budget, releaseState, confirmedNodes, statuses)
	{
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		for _, query := range []string{
			`SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT kind,status,count(*) FROM jobs WHERE payload->>'release_id'=$1 GROUP BY kind,status) s`,
			`SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT node_id,node_epoch,body->>'state' AS state,observed_at FROM deployment_node_events WHERE release_id=$1 ORDER BY observed_at DESC LIMIT 8) s`,
			`SELECT coalesce(jsonb_agg(row_to_json(s)),'[]') FROM (SELECT stage,cause FROM deployment_execution_reports WHERE release_id=$1 LIMIT 8) s`,
		} {
			var metadata []byte
			if err := l.Pool.QueryRow(ctx, query, candidate.ID).Scan(&metadata); err == nil {
				t.Log("initial publication body-free states", string(metadata))
			} else {
				t.Log("initial publication states unavailable")
			}
		}
	}
	t.Fatal("both nodes did not confirm business publication")
	return nil
}

func (l *Lab) CanarySite(t testing.TB) string {
	if l.CanarySiteID != "" {
		return l.CanarySiteID
	}
	b := l.Business(t)
	raw := b.Session.prepareCall(t, "GET", "/sites/"+b.SiteID, nil, 200)
	var site struct{ Draft map[string]any }
	if json.Unmarshal(raw, &site) != nil || site.Draft == nil {
		t.Fatal("canary draft missing")
	}
	site.Draft["enabled"] = false
	site.Draft["domains"] = []string{"deployment-canary.dual.test"}
	delete(site.Draft, "entry_certificate")
	raw = b.Session.prepareCall(t, "POST", "/sites", map[string]any{"name": "gatebeam-upgrade-canary-owned", "group_ids": []string{}, "config": site.Draft}, 201)
	var out struct {
		ID string `json:"resource_id"`
	}
	if json.Unmarshal(raw, &out) != nil || out.ID == "" {
		t.Fatal("missing disabled canary site")
	}
	l.CanarySiteID = out.ID
	return out.ID
}

// RenewRoleTLS simulates a standard role owner's successfully renewed X.509
// pair being delivered atomically at its configured role-only files.
func (l *Lab) RenewRoleTLS(t testing.TB, n *Node, role string) string {
	t.Helper()
	name := "management-api.dual.test"
	certFile, keyFile := "api.pem", "api.key"
	if role == "external-ca" {
		name = "ca.dual.test"
		certFile, keyFile = "tls.pem", "tls.key"
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	csr, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{name}}, key)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := pkidomain.NewPolicy([]string{name}, pkidomain.ServerAuth)
	if e != nil {
		t.Fatal(e)
	}
	serial := big.NewInt(time.Now().UnixNano())
	der, e := l.TestIssuer.SignCSR(csr, policy, []string{name}, serial, time.Now(), time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(private)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: l.TestIssuer.Certificate.Raw})...)
	files := map[string][]byte{certFile: chain, keyFile: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}
	if role == "external-ca" {
		// Replace via the shared fixture directory; the independent process
		// revalidates its TLS pair on the next handshake.
		for name, data := range files {
			l.caFile(t, name, data)
		}
	} else {
		n.WriteRoleFiles(t, role, files)
	}

	return serial.String()
}

func (l *Lab) EnableRoleRenewal(t testing.TB, n *Node, role string) {
	t.Helper()
	name, purpose := "management-api.dual.test", pkidomain.ServerAuth
	if role == "nginx" {
		name, purpose = "gateway-a.dual.test", pkidomain.ClientAuth
		if n == l.Nodes[1] {
			name = "gateway-b.dual.test"
		}
	}
	credentials := l.caEAB(t, name, purpose)
	c := n.Configs[role]
	c.PrivateTLSRenewal = &bootstrap.PrivateTLSRenewal{Origin: caOrigin, Email: "owned@dual.test", EABFile: "/run/gatebeam/acme-eab.json", TrustFile: "/run/gatebeam/roots.pem", CheckSeconds: 1, RenewBeforeSeconds: 7200}
	if role == "management" {
		c.PrivateTLSRenewal.HTTP01WebRoot = "/var/lib/gatebeam/management-acme"
	}

	n.Configs[role] = c
	config, _ := json.Marshal(c)
	n.WriteRoleFiles(t, role, map[string][]byte{"acme-eab.json": credentials, c.Mode + ".json": config})
	n.Compose(t, "up", "-d", "--no-build", "--no-deps", "--force-recreate", role)
	n.Wait(t, role, map[string]string{"nginx": "data", "management": "management"}[role])
}

// This controlled fixture shortens only the retained public leaf to make the
// real role's periodic renewal decision due again without changing wall time.
func (n *Node) MakeRoleRenewalDue(t testing.TB, role string) {
	t.Helper()
	mode := n.Configs[role].Mode
	cert := "api.pem"
	if role == "nginx" {
		cert = "api-client.pem"
	}
	Docker(t, "run", "--rm", "--network", "none", "--read-only", "--user", "0:0", "--cap-drop", "ALL", "--cap-add", "DAC_OVERRIDE", "--cap-add", "CHOWN", "--cap-add", "FOWNER", "--memory", "32m", "--cpus", "0.5", "--pids-limit", "16", "--mount", "type=volume,src="+n.Info.StoragePrefix+"-"+role+"-secret,dst=/seed,readonly", "-v", n.Info.StoragePrefix+"-"+mode+"-capsules:/dest", "--entrypoint", "sh", "gatebeam-edge:local", "-ec", "cp /seed/"+cert+" /dest/renewed-tls.pem; chmod 600 /dest/renewed-tls.pem; chown 101:101 /dest/renewed-tls.pem")
}
