package dns

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	"net/netip"
	"sort"
	"time"
)

// Targets validates all answers on every refresh, including literal members.
type Targets struct {
	Lookup    Lookup
	Protected []netip.Prefix
}

func (r Targets) Resolve(ctx context.Context, t app.Target) (map[string][]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	allowed := []netip.Prefix{}
	for _, s := range t.Config.AllowedNetworks {
		p, e := netip.ParsePrefix(s)
		if e != nil {
			return nil, ErrForbidden
		}
		allowed = append(allowed, p)
	}
	out := map[string][]netip.Addr{}
	for _, m := range t.Config.Members {
		if m.Port < 1 || m.Port > 65535 {
			return nil, ErrForbidden
		}
		if ip, e := netip.ParseAddr(m.Address); e == nil {
			if e = Check(ip, allowed, r.Protected); e != nil {
				return nil, e
			}
			out[m.Address] = []netip.Addr{ip.Unmap()}
		} else {
			ips, e := (Resolver{Lookup: r.Lookup, Allowed: allowed, Protected: r.Protected}).Resolve(ctx, m.Address)
			if e != nil {
				return nil, e
			}
			sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
			out[m.Address] = ips
		}
	}
	return out, nil
}
