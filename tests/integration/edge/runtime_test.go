//go:build integration

package edge_test

import (
	"context"
	"fmt"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/health"
	"gatebeam/internal/modules/deployment/application/release"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/infrastructure/nginx"
	dep "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/modules/deployment/infrastructure/probe"
	"gatebeam/internal/platform/jobs"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAllUnhealthyReturns503AndRecoveryRestoresWeights(t *testing.T) {
	f := setup(t)
	f.addSite(t, "health.test")
	f.snapshot.Targets[0].Config.Health = app.HealthPolicy{Enabled: true}
	p := testkit.Postgres(t)
	ctx := context.Background()
	tx := pg.NewRunner(p)
	repo := dep.NewRuntime(p, jobs.New(p), nil)
	id := "00000000-0000-4000-8000-000000000005"
	if e := tx.Within(ctx, func(sc transaction.Scope) error {
		store := dep.New()
		c := release.Candidate{ID: id, InputDigest: strings.Repeat("a", 64), Snapshot: f.snapshot}
		if e := store.Save(sc, c); e != nil {
			return e
		}
		if _, _, e := store.Queue(sc, id); e != nil {
			return e
		}
		if e := store.RecordOutcome(sc, id, "succeeded", "", ""); e != nil {
			return e
		}
		return store.RecordVerified(sc, id, strings.Repeat("a", 64), "initial")
	}); e != nil {
		t.Fatal(e)
	}
	if e := repo.Prepare(ctx, f.snapshot); e != nil {
		t.Fatal(e)
	}
	bind := func() {
		t.Helper()
		if e := tx.Within(ctx, func(sc transaction.Scope) error {
			var e error
			f.state, e = repo.BindWithin(sc, f.snapshot, f.state)
			return e
		}); e != nil {
			t.Fatal(e)
		}
	}
	bind()
	f.start(t)
	sample := func(healthy bool) {
		t.Helper()
		w, e := repo.Load(ctx, "target", 1)
		if e != nil {
			t.Fatal(e)
		}
		u := health.Update{Work: w, Sequence: w.Sequence + 1, Resolved: map[string][]netip.Addr{f.ip: {netip.MustParseAddr(f.ip)}}}
		for _, m := range w.Target.Config.Members {
			u.Results = append(u.Results, health.Sample{Endpoint: net.JoinHostPort(f.ip, fmt.Sprint(m.Port)), Identity: m.Address + "/" + m.TLSName, Healthy: healthy})
		}
		if _, e = repo.Commit(ctx, u); e != nil {
			t.Fatal(e)
		}
	}
	reload := func() {
		t.Helper()
		bind()
		a, e := (nginx.Compiler{}).Compile(f.snapshot, f.state)
		if e != nil {
			t.Fatal(e)
		}
		for path, data := range a.Files {
			full := filepath.Join(f.root, path)
			if e = os.MkdirAll(filepath.Dir(full), 0700); e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(full, data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		want := f.snapshot.Version + "/" + f.state.Generation
		// A version reply can reach the fresh worker while the retired worker
		// still accepts business traffic. This isolated fixture has no retained
		// connections, so require full old-worker exit (stronger than production's
		// retired-listener barrier), a fresh worker, and then the exact version.
		command(t, "docker", "exec", f.name, "sh", "-c", `
set -eu
master=$(cat /tmp/gatebeam-nginx.pid)
old=$(cat /proc/$master/task/$master/children)
[ -n "$old" ]
nginx -s reload -p /fixture/ -c nginx.conf
for i in $(seq 1 40); do
 retired=1
 for pid in $old; do [ ! -d /proc/$pid ] || retired=0; done
 current=$(cat /proc/$master/task/$master/children)
 fresh=0
 for pid in $current; do case " $old " in *" $pid "*) ;; *) fresh=1 ;; esac; done
 if [ "$retired" = 1 ] && [ "$fresh" = 1 ]; then
  v=$(wget -qO- http://127.0.0.1:9090/version)
  [ "$v" != "$1" ] || exit 0
 fi
 sleep 0.1
done
exit 1`, "reload-barrier", want)
	}
	sample(false)
	sample(false)
	sample(false)
	reload()
	client := f.client("health.test", nil)
	if status, _ := request(t, client, "health.test", "/", "", nil); status != 503 {
		t.Fatal("all unhealthy", status)
	}
	sample(true)
	reload()
	if status, _ := request(t, client, "health.test", "/", "", nil); status != 503 {
		t.Fatal("recovered too soon", status)
	}
	sample(true)
	reload()
	counts := map[string]int{}
	for i := 0; i < 16; i++ {
		status, data := request(t, client, "health.test", "/", "", nil)
		if status != 200 {
			t.Fatal("recovery", status)
		}
		counts[data["sni"]]++
	}
	if counts["a.internal.test"] != 4 || counts["b.internal.test"] != 12 {
		t.Fatal("weights not restored", counts)
	}
	if e := repo.Flush(ctx); e != nil {
		t.Fatal(e)
	}
	var n int
	if e := p.QueryRow(ctx, "SELECT count(*) FROM jobs WHERE kind='deployment.generation'").Scan(&n); e != nil || n != 1 {
		t.Fatal("not coalesced", n, e)
	}
}
func TestPreflightPreservesAOPAndMTLS(t *testing.T) {
	f := setup(t)
	c := f.addSite(t, "probe-mtls.test")
	clientCA := newCA(t, "probe clients")
	cert, key := clientCA.leaf(t, "authorized-probe", true)
	f.state.Materials["client-trust"] = edge.Material{Revision: 1, TrustPEM: clientCA.pem, CRLPEM: clientCA.crl(t)}
	c.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "client-trust", Revision: 1}, Depth: 2, Revocation: "crl"}
	c = f.addSite(t, "probe-cf.test")
	c.Cloudflare = app.CFPolicy{Mode: "proxied", TrustedProxyNetworks: []string{"10.254.254.0/24"}}
	f.state.Cloudflare = edge.CloudflareSet{ValidUntil: time.Now().Add(time.Hour), Generation: "fixture-official", Networks: []netip.Prefix{netip.MustParsePrefix("10.254.254.0/24"), netip.MustParsePrefix(command(t, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}", f.name) + "/32")}}
	c = f.addSite(t, "probe-aop.test")
	c.Cloudflare = app.CFPolicy{Mode: "proxied", RequireOriginPull: true}
	c.ClientVerification = app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "approved-aop", Revision: 1}, Depth: 2, Revocation: "crl"}
	f.state.Materials["approved-aop"] = edge.Material{Revision: 1, TrustPEM: clientCA.pem, CRLPEM: clientCA.crl(t), OriginPullAuthorized: true}
	f.start(t)
	address := netip.MustParseAddrPort("127.0.0.1:" + f.port)
	request := health.Probe{Address: address, Protocol: "https", HTTPHost: "probe-mtls.test", TLSName: "probe-mtls.test", Path: "/", Trust: &edge.Material{TrustPEM: f.ca.pem}}
	check := func(p health.Probe) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return (probe.HTTP{}).Check(ctx, p)
	}
	if check(request) == nil {
		t.Fatal("missing standard client certificate accepted")
	}
	request.ClientCertificate = &edge.Material{CertificatePEM: cert, KeyPEM: key}
	if e := check(request); e != nil {
		t.Fatal("authorized standard client rejected", e)
	}
	request.TLSName = "wrong.test"
	if check(request) == nil {
		t.Fatal("wrong SNI accepted")
	}
	request.TLSName = "probe-aop.test"
	request.HTTPHost = "probe-aop.test"
	request.ClientCertificate = nil
	if check(request) == nil {
		t.Fatal("missing standard origin-pull client identity accepted")
	}
	// This trusted fixture is an owned CA and peer network, not a claim about a
	// live Cloudflare path. It proves the adapter can present standard mTLS.
	request.ClientCertificate = &edge.Material{CertificatePEM: cert, KeyPEM: key}
	if e := check(request); e != nil {
		t.Fatal("owned approved-AOP fixture client rejected", e)
	}
	request.TLSName = "probe-cf.test"
	request.HTTPHost = "probe-cf.test"
	request.ClientCertificate = nil
	if check(request) == nil {
		t.Fatal("direct connection bypassed CF trust")
	}
}
