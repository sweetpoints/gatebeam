//go:build integration

package multinode_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	age "filippo.io/age"
	fixture "gatebeam/tests/fixtures/multinode"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPrivateTLSRotationAndRevocationAcrossRestart(t *testing.T) {
	l := fixture.Start(t)
	b := l.Business(t)
	a := l.Nodes[0]
	apiID, caID := a.Compose(t, "ps", "-q", "management"), a.Compose(t, "ps", "-q", "internal-ca")
	checkSerial := func(client *http.Client, url, serial string) {
		t.Helper()
		r, e := client.Get(url)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		if r.TLS == nil || r.TLS.PeerCertificates[0].SerialNumber.String() != serial {
			t.Fatal("running role kept old TLS identity")
		}
	}
	apiSerial := l.RenewRoleTLS(t, a, "management")
	checkSerial(a.APIClient, "https://management-api.dual.test/auth/session", apiSerial)
	caSerial := l.RenewRoleTLS(t, a, "internal-ca")
	checkSerial(a.CAClient, "https://ca.dual.test:8444/acme/server/directory", caSerial)
	if apiID != a.Compose(t, "ps", "-q", "management") || caID != a.Compose(t, "ps", "-q", "internal-ca") {
		t.Fatal("certificate load restarted role")
	}
	// A valid fresh issuer CRL revokes the actual gateway leaf, not its login.
	certPEM, e := os.ReadFile(filepath.Join(a.Secrets["nginx"], "api-client.pem"))
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(certPEM)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	old, e := os.ReadFile(filepath.Join(a.Secrets["management"], "api-client.crl"))
	if e != nil {
		t.Fatal(e)
	}
	rootList := []byte{}
	rest := old
	for len(rest) > 0 {
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		crl, _ := x509.ParseRevocationList(block.Bytes)
		if crl != nil && crl.CheckSignatureFrom(l.TestIssuer.Certificate) != nil {
			rootList = append(rootList, pem.EncodeToMemory(block)...)
		}
		rest = next
	}
	der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now().Add(-time.Second), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Second)}}}, l.TestIssuer.Certificate, l.TestIssuer.Signer)
	if e != nil {
		t.Fatal(e)
	}
	a.WriteRoleFiles(t, "management", map[string][]byte{"api-client.crl": append(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), rootList...)})
	if r, e := a.APIClient.Get("https://management-api.dual.test/auth/session"); e == nil {
		r.Body.Close()
		t.Fatal("revoked gateway admitted by private API")
	}
	if b.Get(t, a, "/") != 200 {
		t.Fatal("private API status affected unrelated business")
	}
	// Restoring the old signed list does not erase the retained status minimum.
	a.WriteRoleFiles(t, "management", map[string][]byte{"api-client.crl": old})
	a.Compose(t, "rm", "-sf", "management")
	a.Compose(t, "up", "-d", "--no-build", "--no-deps", "management")
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://management-api.dual.test/auth/session", nil)
	if r, e := a.APIClient.Do(request); e == nil {
		r.Body.Close()
		t.Fatal("old CRL revived revoked identity after role cold restart")
	}
	code, _ := l.Nodes[1].Request(t, "GET", "/sites/"+b.SiteID, nil, b.Session.Cookie, b.Session.CSRF)
	if code != 200 {
		t.Fatal("peer management failed", code)
	}
	t.Log("actual API and CA listeners automatically loaded replacement X.509 pairs without process restart; actual revoked gateway rejected and persistent minimum blocked stale signed CRL after API replacement")
}
func TestFunctionalCanaryRejectsQueryAndArchiveFailures(t *testing.T) {
	l := fixture.Start(t)
	b := l.Business(t)
	a := l.Nodes[0]
	if b.Get(t, a, "/") != 200 {
		t.Fatal("missing business traffic")
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		_, e := a.TryControl(t, "background-jobs", "/capabilities/verify", struct{}{})
		if e == nil {
			break
		}
		if time.Now().After(deadline) {
			a.LogQueryCapabilityFailure(t)
			t.Fatal("actual local query capability failed", e)
		}
		time.Sleep(100 * time.Millisecond)
	}
	a.Compose(t, "stop", "--timeout", "2", "log-query")
	if _, e := a.TryControl(t, "background-jobs", "/capabilities/verify", struct{}{}); e == nil {
		t.Fatal("socket health masqueraded as query result")
	}
	a.Compose(t, "start", "log-query")
	a.Wait(t, "log-query", "query")
	archive := l.EnableArchive(t)
	archive.WaitBoth(t)
	if _, e := a.TryControl(t, "background-jobs", "/capabilities/verify", struct{}{}); e != nil {
		a.LogQueryCapabilityFailure(t)
		t.Fatal("real S3 write/read and archived DuckDB query failed", e)
	}
	archive.DisconnectReaders(t)
	if _, e := a.TryControl(t, "background-jobs", "/capabilities/verify", struct{}{}); e == nil {
		t.Fatal("unavailable archive accepted as functional capability")
	}
	if b.Get(t, a, "/") != 200 {
		t.Fatal("canary failure stopped unrelated data")
	}
}

func TestPrivateRolesObtainAndAutomaticallyLoadStandardACME(t *testing.T) {
	l := fixture.Start(t)
	business := l.Business(t)
	a := l.Nodes[0]
	leafSerial := func(client *http.Client, url string) string {
		t.Helper()
		r, e := client.Get(url)
		if e != nil {
			t.Fatal(e)
		}
		r.Body.Close()
		return r.TLS.PeerCertificates[0].SerialNumber.String()
	}
	oldAPI, oldCA := leafSerial(a.APIClient, "https://management-api.dual.test/auth/session"), leafSerial(a.CAClient, "https://ca.dual.test:8444/acme/server/directory")
	for _, role := range []string{"management", "internal-ca", "nginx"} {
		l.EnableRoleRenewal(t, a, role)
	}
	deadline := time.Now().Add(25 * time.Second)
	for {
		ready := true
		for _, role := range []string{"management", "internal-ca", "nginx"} {
			ready = ready && a.Health(t, role).Details["tls_renewal"] == "ready"
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			for _, role := range []string{"management", "internal-ca", "nginx"} {
				t.Log(role, a.Health(t, role), a.Compose(t, "logs", "--tail", "6", role))
			}
			t.Fatal("standard private role issuance did not complete")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if leafSerial(a.APIClient, "https://management-api.dual.test/auth/session") == oldAPI || leafSerial(a.CAClient, "https://ca.dual.test:8444/acme/server/directory") == oldCA {
		t.Fatal("renewed certificate was not automatically loaded")
	}
	code, _ := a.Request(t, "GET", "/sites/"+business.SiteID, nil, business.Session.Cookie, business.Session.CSRF)
	if code != 200 {
		t.Fatal("renewed gateway client not applied", code)
	}
	firstRenewed := leafSerial(a.APIClient, "https://management-api.dual.test/auth/session")
	a.MakeRoleRenewalDue(t, "management")
	deadline = time.Now().Add(10 * time.Second)
	for {
		current := leafSerial(a.APIClient, "https://management-api.dual.test/auth/session")
		if current != firstRenewed && current != oldAPI {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("periodic standard ACME renewal did not replace due leaf")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var count int
	if e := l.Pool.QueryRow(t.Context(), `SELECT count(*) FROM pki_certificates`).Scan(&count); e != nil || count < 4 {
		t.Fatal("standard server/client orders did not issue", count, e)
	}
	if business.Get(t, a, "/") != 200 {
		t.Fatal("role renewal interrupted business")
	}
	t.Log("one initial MFA/EAB grant per role; unchanged standard ACME v2 client completed shared HTTP01 for API/CA and node-local HTTP01 for gateway client; own existing keys remained in owning role and new leaves auto-loaded without manual configuration publication")
}

func TestCapsuleEnabledMaintenanceSurvivesEdgeControlRestart(t *testing.T) {
	l := fixture.Start(t)
	business := l.Business(t)
	a := l.Nodes[0]
	offline, e := age.GenerateX25519Identity()
	if e != nil {
		t.Fatal(e)
	}
	cfg := a.Configs["nginx"]
	cfg.BackupRecipient = offline.Recipient().String()
	cfg.BackupEpoch = "maintenance-proof"
	cfg.BackupCapsuleDirectory = "/var/lib/gatebeam/capsules"
	a.Configs["nginx"] = cfg
	raw, _ := json.Marshal(cfg)
	a.WriteRoleFiles(t, "nginx", map[string][]byte{"edge.json": raw})
	a.Compose(t, "up", "-d", "--no-build", "--no-deps", "--force-recreate", "nginx")
	a.Wait(t, "nginx", "data")
	set := func(n *fixture.Node, unavailable bool) string {
		t.Helper()
		var ack struct {
			Digest string `json:"desired_digest"`
		}
		if json.Unmarshal(n.Control(t, "nginx", "/management-upstreams", map[string]any{"address": a.Info.PrivateAddress + ":9443", "unavailable": unavailable}), &ack) != nil || ack.Digest == "" {
			t.Fatal("missing maintenance receipt")
		}
		return ack.Digest
	}
	wait := func(n *fixture.Node, digest string) {
		t.Helper()
		end := time.Now().Add(8 * time.Second)
		for {
			if n.Health(t, "nginx").Details["management_config_digest"] == digest {
				return
			}
			if time.Now().After(end) {
				t.Fatal("control did not confirm maintenance after capsule update", n.Compose(t, "logs", "--tail", "6", "nginx"))
			}
			time.Sleep(40 * time.Millisecond)
		}
	}
	for _, n := range l.Nodes {
		wait(n, set(n, true))
	}
	before := a.Compose(t, "ps", "-q", "nginx")
	a.Compose(t, "rm", "-sf", "nginx")
	a.Compose(t, "up", "-d", "--no-build", "--no-deps", "nginx")
	a.Wait(t, "nginx", "data")
	if a.Compose(t, "ps", "-q", "nginx") == before {
		t.Fatal("not a cold edge restart")
	}
	for _, n := range l.Nodes {
		wait(n, set(n, false))
	}
	if business.Get(t, a, "/") != 200 {
		t.Fatal("capsule update interrupted business")
	}
	t.Log("real node capsule enabled; remove applied on both gateways, edge process replaced, same recovery epoch re-export succeeded, control resumed and both native restore receipts confirmed")
}
func TestWorkerConstructorFailureBlocksReadinessButPreservesLocalQueries(t *testing.T) {
	l := fixture.Start(t)
	business := l.Business(t)
	a := l.Nodes[0]
	cfg := a.Configs["background-jobs"]
	cfg.CAOrigin = "https://ca.dual.test:8444"
	cfg.CertificateACMETransportTrustFile = "/run/gatebeam/bad-ca.pem"
	a.Configs["background-jobs"] = cfg
	raw, _ := json.Marshal(cfg)
	a.WriteRoleFiles(t, "background-jobs", map[string][]byte{"worker.json": raw, "bad-ca.pem": []byte("invalid trusted CA")})
	a.Compose(t, "up", "-d", "--no-build", "--no-deps", "--force-recreate", "background-jobs")
	until := time.Now().Add(8 * time.Second)
	for {
		state, probeErr := a.ProbeHealth(t, "background-jobs")
		log := a.Compose(t, "logs", "--tail", "6", "background-jobs")
		if probeErr == nil && state.Live && !state.Ready["global-jobs"] && strings.Contains(log, "certificates unavailable") {
			break
		}
		if time.Now().After(until) {
			t.Fatal("broken component state not observed before deadline", state, probeErr)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, e := a.TryControl(t, "background-jobs", "/capabilities/verify", struct{}{}); e == nil {
		t.Fatal("broken role canary succeeded")
	}
	if business.Get(t, a, "/") != 200 {
		t.Fatal("control component failure stopped business")
	}
	page := business.Query(t, "local")
	if page.Job.State != "succeeded" || page.Job.Coverage != "local_complete" {
		t.Fatal("independent local queries starved by certificate component failure", page.Job.State, page.Job.Coverage)
	}
}
