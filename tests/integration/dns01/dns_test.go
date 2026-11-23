//go:build integration

package dns01_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	app "gatebeam/internal/modules/certificates/application"
	client "gatebeam/internal/modules/certificates/infrastructure/lego"
	"gatebeam/internal/platform/secrets"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/miekg/dns"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const pebbleImage = "ghcr.io/letsencrypt/pebble@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
const nativeImage = "nginx@sha256:785835ea65db4bba6f021acc0f3be91b0fef76a53fe41f8588c6698d2aed0606"

func command(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if e != nil {
		t.Fatalf("owned DNS fixture docker %s: %v: %s", args[0], e, b)
	}
	return strings.TrimSpace(string(b))
}
func TestOwnedDNS01StandardIssuance(t *testing.T) {
	if os.Getenv("GATEBEAM_DNS01_NATIVE") == "1" {
		native(t)
		return
	}
	binary := os.Getenv("GATEBEAM_DNS01_BINARY")
	if binary == "" {
		t.Fatal("required native DNS acceptance binary absent; run scripts/check-dns01.sh")
	}
	dir := t.TempDir()
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"pebble.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	config := []byte(`{"pebble":{"listenAddress":"0.0.0.0:14000","managementListenAddress":"0.0.0.0:15000","certificate":"/lab/cert.pem","privateKey":"/lab/key.pem","httpPort":5002,"tlsPort":5001,"keyAlgorithm":"ecdsa","retryAfter":{"authz":1,"order":1}}}`)
	for name, b := range map[string][]byte{"config.json": config, "cert.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
		if e := os.WriteFile(filepath.Join(dir, name), b, 0444); e != nil {
			t.Fatal(e)
		}
	}
	name := fmt.Sprintf("gatebeam-dns01-%d", time.Now().UnixNano())
	command(t, "network", "create", "--internal", name)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		exec.CommandContext(ctx, "docker", "rm", "-f", name+"-ca", name+"-test").Run()
		exec.CommandContext(ctx, "docker", "network", "rm", name).Run()
	})
	command(t, "run", "-d", "--name", name+"-ca", "--network", name, "--network-alias", "pebble.test", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--cpus", ".5", "--pids-limit", "64", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--mount", "type=bind,src="+dir+",dst=/lab,readonly", "-e", "PEBBLE_VA_NOSLEEP=1", pebbleImage, "-config", "/lab/config.json", "-dnsserver", "dns.owned.test:53")
	// Real recursive and authoritative UDP/TCP DNS exist solely on this owned
	// network. Neither the host resolver nor production DNS settings are changed.
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	args := []string{"run", "--rm", "--name", name + "-test", "--network", name, "--network-alias", "dns.owned.test", "--network-alias", "ns.owned.test", "--user", "101:101", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--memory", "128m", "--cpus", ".5", "--pids-limit", "64", "--tmpfs", "/tmp:size=16m,mode=1777", "--mount", "type=bind,src=" + dir + ",dst=/lab,readonly", "--mount", "type=bind,src=" + binary + ",dst=/fixture,readonly", "-e", "GATEBEAM_DNS01_NATIVE=1", "--entrypoint", "/fixture", nativeImage, "-test.run", "^TestOwnedDNS01StandardIssuance$", "-test.v", "-test.timeout=60s"}
	b, e := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	t.Log(string(b))
	if e != nil {
		t.Log(command(t, "logs", name+"-ca"))
		t.Fatal("native DNS01 gate failed", e)
	}
}

type record struct {
	ID, Type, Name, Content, Comment string
	TTL                              int
}

func native(t *testing.T) {
	var mu sync.Mutex
	records := map[string]record{"unrelated": {ID: "unrelated", Type: "TXT", Name: "_acme-challenge.service.owned.test", Content: "preserve-this"}}
	var recursive, authoritative, caQueries, created, deleted int
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		out := new(dns.Msg)
		out.SetReply(r)
		out.Authoritative = true
		mu.Lock()
		defer mu.Unlock()
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeSOA:
				out.Answer = append(out.Answer, &dns.SOA{Hdr: dns.RR_Header{Name: "owned.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 1}, Ns: "ns.owned.test.", Mbox: "hostmaster.owned.test.", Serial: 1, Refresh: 1, Retry: 1, Expire: 60, Minttl: 1})
			case dns.TypeNS:
				out.Answer = append(out.Answer, &dns.NS{Hdr: dns.RR_Header{Name: "owned.test.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 1}, Ns: "ns.owned.test."})
			case dns.TypeTXT:
				if strings.HasPrefix(w.RemoteAddr().String(), "127.") {
					recursive++
				} else if r.RecursionDesired {
					caQueries++
				} else {
					authoritative++
				}
				for _, v := range records {
					if q.Name == v.Name+"." {
						out.Answer = append(out.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 1}, Txt: []string{v.Content}})
					}
				}
			}
		}
		if e := w.WriteMsg(out); e != nil {
			t.Error("DNS response failed", e)
		}
	})
	packet, e := net.ListenPacket("udp", ":53")
	if e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("tcp", ":53")
	if e != nil {
		packet.Close()
		t.Fatal(e)
	}
	udp := &dns.Server{PacketConn: packet, Handler: handler}
	tcp := &dns.Server{Listener: listener, Handler: handler}
	go udp.ActivateAndServe()
	go tcp.ActivateAndServe()
	defer udp.Shutdown()
	defer tcp.Shutdown()
	cf := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer owned-token" || !strings.HasPrefix(r.URL.Path, "/zones/"+strings.Repeat("a", 32)+"/dns_records") {
			w.WriteHeader(403)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		var result any
		switch r.Method {
		case "POST":
			var v record
			if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&v) != nil || v.Type != "TXT" || v.TTL != 60 || !strings.HasPrefix(v.Comment, "gatebeam-acme:") {
				w.WriteHeader(400)
				return
			}
			v.ID = "owned"
			records[v.ID] = v
			created++
			result = v
		case "GET":
			v, ok := records[filepath.Base(r.URL.Path)]
			if !ok {
				w.WriteHeader(404)
				return
			}
			result = v
		case "DELETE":
			if filepath.Base(r.URL.Path) != "owned" {
				w.WriteHeader(403)
				return
			}
			delete(records, "owned")
			deleted++
		default:
			w.WriteHeader(405)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"success": true, "result": result})
	}))
	defer cf.Close()
	roots := x509.NewCertPool()
	b, e := os.ReadFile("/lab/cert.pem")
	if e != nil || !roots.AppendCertsFromPEM(b) {
		t.Fatal("transport trust missing", e)
	}
	roots.AddCert(cf.Certificate())
	hc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}}
	old := dns01.DefaultClient()
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: []string{"127.0.0.1:53"}, Timeout: time.Second}))
	defer dns01.SetDefaultClient(old)
	path := filepath.Join(t.TempDir(), "provider.agekey")
	if e := secrets.EnsureIdentity(path); e != nil {
		t.Fatal(e)
	}
	store, e := secrets.New(path)
	if e != nil {
		t.Fatal(e)
	}
	rec := func(kind, id string, body any, secret []byte) app.Record {
		b, e := json.Marshal(body)
		if e != nil {
			t.Fatal(e)
		}
		v := app.Record{Resource: app.Resource{Kind: kind, ID: id, Revision: 1, Enabled: true, Body: b}}
		if secret != nil {
			label, _ := json.Marshal([]any{kind, id, int64(1)})
			v.Secret, e = store.Seal("certificates/"+string(label), secret)
			if e != nil {
				t.Fatal(e)
			}
		}
		return v
	}
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	secret, _ := json.Marshal(struct{ Key, EAB []byte }{Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})})
	work := app.Work{Token: "owned-dns01", Account: rec("provider-account", "account", app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, secret), Spec: rec("spec", "spec", app.Spec{Names: []string{"service.owned.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: "account", Challenge: "dns-01", CredentialIDs: []string{"credential"}}, nil), Credentials: []app.Record{rec("dns-credential", "credential", app.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "owned.test"}, []byte("owned-token"))}}
	c := client.Client{Secrets: store, HTTPClient: hc, Directories: map[string]string{"letsencrypt": "https://pebble.test:14000/dir"}, DNSBase: cf.URL}
	issued, e := c.Obtain(t.Context(), work)
	if e != nil {
		t.Fatal(e)
	}
	response, e := hc.Get("https://pebble.test:15000/roots/0")
	if e != nil {
		t.Fatal(e)
	}
	rootPEM, e := io.ReadAll(io.LimitReader(response.Body, 65536))
	response.Body.Close()
	if e != nil || response.StatusCode != 200 {
		t.Fatal("owned root unavailable", e)
	}
	trusted := x509.NewCertPool()
	if !trusted.AppendCertsFromPEM(rootPEM) {
		t.Fatal("owned root invalid")
	}
	intermediates := x509.NewCertPool()
	block, rest := pem.Decode(issued.CertificatePEM)
	if block == nil {
		t.Fatal("leaf missing")
	}
	leaf, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	intermediates.AppendCertsFromPEM(rest)
	if _, e := leaf.Verify(x509.VerifyOptions{Roots: trusted, Intermediates: intermediates, DNSName: "service.owned.test"}); e != nil {
		t.Fatal(e)
	}
	mu.Lock()
	defer mu.Unlock()
	if created != 1 || deleted != 1 || len(records) != 1 || records["unrelated"].Content != "preserve-this" || recursive == 0 || authoritative == 0 || caQueries == 0 {
		t.Fatalf("DNS proof incomplete created=%d deleted=%d remaining=%d recursive=%d authoritative=%d CA=%d", created, deleted, len(records), recursive, authoritative, caQueries)
	}
	t.Logf("standard DNS01 leaf verified; owned CF create/delete=%d/%d unrelated TXT retained; actual recursive=%d authoritative=%d CA TXT=%d", created, deleted, recursive, authoritative, caQueries)
}
