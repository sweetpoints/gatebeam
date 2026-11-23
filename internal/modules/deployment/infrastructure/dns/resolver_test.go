package dns

import (
	"context"
	"encoding/binary"
	app "gatebeam/internal/modules/deployment/application"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type lookup struct {
	ips []netip.Addr
	err error
}

func (l lookup) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return l.ips, l.err
}
func TestEveryRefreshRejectsRebindingAndControlTargets(t *testing.T) {
	r := Resolver{Allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, Protected: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}, Lookup: lookup{ips: []netip.Addr{netip.MustParseAddr("10.0.0.9")}}}
	got, e := r.Resolve(context.Background(), "backend.internal")
	if e != nil || len(got) != 1 {
		t.Fatal(got, e)
	}
	for _, bad := range []string{"127.0.0.1", "169.254.169.254", "10.0.0.1", "8.8.8.8", "fd00:ec2::254"} {
		r.Lookup = lookup{ips: []netip.Addr{netip.MustParseAddr("10.0.0.9"), netip.MustParseAddr(bad)}}
		if _, e = r.Resolve(context.Background(), "backend.internal"); e == nil {
			t.Fatalf("rebound target %s accepted", bad)
		}
	}
}
func TestIPv6MetadataAlwaysProtected(t *testing.T) {
	if Check(netip.MustParseAddr("fd00:ec2::254"), []netip.Prefix{netip.MustParsePrefix("fc00::/7")}, nil) == nil {
		t.Fatal("AWS IPv6 metadata target accepted")
	}
}

func TestRealDNSRefreshRejectsReboundAddress(t *testing.T) {
	socket, e := net.ListenPacket("udp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer socket.Close()
	var answer atomic.Value
	answer.Store(netip.MustParseAddr("10.0.0.9"))
	done := make(chan struct{})
	defer func() { socket.Close(); <-done }()
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, peer, e := socket.ReadFrom(buf)
			if e != nil {
				return
			}
			if n < 17 {
				continue
			}
			q := append([]byte{}, buf[:n]...)
			end := 12
			for end < n && q[end] != 0 {
				end += int(q[end]) + 1
			}
			if end+5 > n {
				continue
			}
			end += 5
			reply := append([]byte{}, q[:end]...)
			reply[2] = 0x81
			reply[3] = 0x80
			binary.BigEndian.PutUint16(reply[6:8], 0)
			if binary.BigEndian.Uint16(q[end-4:end-2]) == 1 {
				binary.BigEndian.PutUint16(reply[6:8], 1)
				ip := answer.Load().(netip.Addr).As4()
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4)
				reply = append(reply, ip[:]...)
			}
			socket.WriteTo(reply, peer)
		}
	}()
	lookup := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "udp", socket.LocalAddr().String())
	}}
	r := Resolver{Lookup: lookup, Timeout: time.Second, Allowed: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if ips, e := r.Resolve(context.Background(), "owned.internal.test"); e != nil || len(ips) != 1 || ips[0].String() != "10.0.0.9" {
		t.Fatal(ips, e)
	}
	answer.Store(netip.MustParseAddr("169.254.169.254"))
	if _, e := r.Resolve(context.Background(), "owned.internal.test"); e == nil {
		t.Fatal("real DNS rebinding accepted")
	}
}

func TestGCPIPv6MetadataAlwaysProtected(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("fc00::/7")}
	metadata := netip.MustParseAddr("fd20:ce::254")
	t.Run("literal", func(t *testing.T) {
		if Check(metadata, allowed, nil) == nil {
			t.Fatal("GCP IPv6 metadata literal accepted under authorized ULA range")
		}
	})
	t.Run("DNS answer", func(t *testing.T) {
		r := Resolver{Allowed: allowed, Lookup: lookup{ips: []netip.Addr{netip.MustParseAddr("fd20:ce::9"), metadata}}}
		if _, e := r.Resolve(context.Background(), "backend.internal.test"); e == nil {
			t.Fatal("GCP IPv6 metadata DNS answer accepted under authorized ULA range")
		}
	})
}

type deadlineLookup struct{ deadlines []time.Time }

func (l *deadlineLookup) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	deadline, _ := ctx.Deadline()
	l.deadlines = append(l.deadlines, deadline)
	time.Sleep(time.Millisecond)
	return []netip.Addr{netip.MustParseAddr("10.0.0.2")}, nil
}
func TestTargetDNSRefreshSharesOneBoundedDeadline(t *testing.T) {
	lookup := &deadlineLookup{}
	_, e := (Targets{Lookup: lookup}).Resolve(context.Background(), app.Target{Config: app.TargetConfig{AllowedNetworks: []string{"10.0.0.0/8"}, Members: []app.TargetMember{{Address: "a.internal", Port: 80}, {Address: "b.internal", Port: 81}}}})
	if e != nil || len(lookup.deadlines) != 2 || !lookup.deadlines[0].Equal(lookup.deadlines[1]) {
		t.Fatal("DNS members gained separate unbounded aggregate budgets", lookup.deadlines, e)
	}
}
