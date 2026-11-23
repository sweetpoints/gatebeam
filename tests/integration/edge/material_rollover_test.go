package edge_test

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"math/big"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reloadP5(t *testing.T, f *fixture) {
	t.Helper()
	artifact, e := (nginx.Compiler{}).Compile(f.snapshot, f.state)
	if e != nil {
		t.Fatal(e)
	}
	// Fixtures preserve each compiled material set in an immutable generation
	// directory, matching production's filesystem artifact replacement semantics.
	directory := filepath.Join(f.root, "releases", artifact.ID)
	if e = os.MkdirAll(directory, 0755); e != nil {
		t.Fatal(e)
	}
	for name, data := range artifact.Files {
		path := filepath.Join(directory, name)
		if e = os.MkdirAll(filepath.Dir(path), 0755); e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	// The fixture master was started at /fixture; include the immutable complete
	// configuration via its absolute directory so relative material paths remain
	// rooted at that generation, instead of overwriting loaded key/CRL paths.
	config := artifact.Files["nginx.conf"]
	config = []byte(strings.ReplaceAll(string(config), "materials/", "/fixture/releases/"+artifact.ID+"/materials/"))
	if e = os.WriteFile(filepath.Join(f.root, "nginx.conf"), config, 0600); e != nil {
		t.Fatal(e)
	}
	command(t, "docker", "exec", f.name, "sh", "-c", `set -eu
master=$(cat /tmp/gatebeam-nginx.pid)
old=$(cat /proc/$master/task/$master/children)
nginx -t -p /fixture/ -c nginx.conf
nginx -s reload -p /fixture/ -c nginx.conf
for i in $(seq 1 40); do
 retired=1
 for pid in $old; do [ ! -d /proc/$pid ] || retired=0; done
 [ "$retired" = 0 ] || exit 0
 sleep 0.1
done
exit 1`)
}
func TestNativeAuthoritativeCloudflareRemoval(t *testing.T) {
	f := setup(t)
	policy := f.addSite(t, "removed.test")
	gateway := command(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", f.name)
	policy.Cloudflare = app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{gateway + "/32"}}
	f.state.Cloudflare = edge.CloudflareSet{Generation: "cf-before", ValidUntil: time.Now().Add(time.Hour), Networks: []netip.Prefix{netip.MustParsePrefix(gateway + "/32")}}
	f.start(t)
	client := f.client("removed.test", nil)
	headers := map[string]string{"CF-Connecting-IP": "203.0.113.8"}
	if code, _ := request(t, client, "removed.test", "/", "", headers); code != 200 {
		t.Fatal(code)
	}
	// A valid new authoritative set no longer intersects the operator narrowing.
	f.state.Cloudflare.Networks = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	f.state.Cloudflare.Generation = "cf-after"
	f.state.Generation = "removed-generation"
	reloadP5(t, f)
	if code, _ := request(t, client, "removed.test", "/", "", headers); code != 403 {
		t.Fatal("removed peer retains trust after native reload", code)
	}
	f.state.Cloudflare.Networks = nil
	f.state.Cloudflare.Generation = "cf-empty"
	f.state.Generation = "empty-generation"
	reloadP5(t, f)
	if code, _ := request(t, client, "removed.test", "/", "", headers); code != 403 {
		t.Fatal("empty official set accepts peer", code)
	}
}
func TestNativeSameDNTrustRollover(t *testing.T) {
	f := setup(t)
	site := f.addSite(t, "rollover.test")
	old, new := newCA(t, "same issuer DN"), newCA(t, "same issuer DN")
	oldCert, oldKey := old.leaf(t, "old-client.test", true)
	newCert, newKey := new.leaf(t, "new-client.test", true)
	oldPair, e := tls.X509KeyPair(oldCert, oldKey)
	if e != nil {
		t.Fatal(e)
	}
	newPair, e := tls.X509KeyPair(newCert, newKey)
	if e != nil {
		t.Fatal(e)
	}
	site.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "rollover", Revision: 1}, Depth: 2, Revocation: "crl"}
	f.state.Materials["rollover"] = edge.Material{Revision: 1, TrustPEM: append(append([]byte{}, old.pem...), new.pem...), CRLPEM: append(old.crl(t), new.crl(t)...)}
	f.start(t)
	oldClient, newClient := f.client("rollover.test", &oldPair), f.client("rollover.test", &newPair)
	for _, client := range []*http.Client{oldClient, newClient} {
		if code, _ := request(t, client, "rollover.test", "/", "", nil); code != 200 {
			t.Fatal("same-DN overlap rejected", code)
		}
	}
	block, _ := pem.Decode(newCert)
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	list, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}}, new.cert, new.key)
	if e != nil {
		t.Fatal(e)
	}
	material := f.state.Materials["rollover"]
	material.CRLPEM = append(old.crl(t), pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: list})...)
	f.state.Materials["rollover"] = material
	f.state.Generation = "revoked-new-key"
	reloadP5(t, f)
	if code, _ := request(t, oldClient, "rollover.test", "/", "", nil); code != 200 {
		t.Fatal("revoked new key also rejected old key", code)
	}
	if code, _ := request(t, newClient, "rollover.test", "/", "", nil); code == 200 {
		t.Fatal("new-key CRL did not revoke new client")
	}
}
