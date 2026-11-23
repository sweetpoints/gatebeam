package nginx_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	"math/big"
	"net/netip"
	"testing"
	"time"
)

func TestSameDNTrustRolloverRequiresBothKeyCRLs(t *testing.T) {
	s, r, oldCA, _ := revocationFixture(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := *oldCA
	template.SerialNumber = big.NewInt(10)
	template.SubjectKeyId = nil
	template.PublicKey = &key.PublicKey
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: r.Now.Add(-time.Minute), NextUpdate: r.Now.Add(time.Hour)}, ca, key)
	if err != nil {
		t.Fatal(err)
	}
	m := r.Materials["trust"]
	m.TrustPEM = append(m.TrustPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	r.Materials["trust"] = m
	if _, err = (nginx.Compiler{}).Compile(s, r); err == nil {
		t.Fatal("new key without CRL accepted")
	}
	m.CRLPEM = append(m.CRLPEM, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})...)
	r.Materials["trust"] = m
	if _, err = (nginx.Compiler{}).Compile(s, r); err != nil {
		t.Fatalf("valid same-DN/different-key overlap rejected: %v", err)
	}
	m.CRLPEM = append(m.CRLPEM, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl})...)
	r.Materials["trust"] = m
	if _, err = (nginx.Compiler{}).Compile(s, r); err == nil {
		t.Fatal("duplicate CRL accepted")
	}
}

func TestAuthoritativeCloudflareRemovalClosesSite(t *testing.T) {
	s := app.Snapshot{Version: "v1", Sites: []app.Site{{ID: "site", Revision: 1, Config: app.SiteConfig{Enabled: true, Domains: []string{"entry.test"}, Cloudflare: app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{"192.0.2.0/24"}}}}}}
	for _, networks := range [][]netip.Prefix{nil, {netip.MustParsePrefix("198.51.100.0/24")}} {
		r := edge.RuntimeState{Generation: "g2", Cloudflare: edge.CloudflareSet{Generation: "cf2", Networks: networks}}
		artifact, err := (nginx.Compiler{}).Compile(s, r)
		if err != nil {
			t.Fatalf("authoritative removal must generate closed site, not retain stale config: %v", err)
		}
		config := artifact.Files["nginx.conf"]
		if !bytes.Contains(config, []byte("return 403;")) || bytes.Contains(config, []byte("set_real_ip_from")) {
			t.Fatalf("removed trust retained: %s", config)
		}
	}
}
