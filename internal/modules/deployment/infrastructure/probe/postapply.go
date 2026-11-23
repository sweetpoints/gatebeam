package probe

import (
	"context"
	"gatebeam/internal/modules/deployment/application/health"
	edge "gatebeam/internal/modules/deployment/application/runtime"
)

func (h HTTP) CheckRoute(ctx context.Context, p edge.RouteProbe) error {
	return h.Check(ctx, health.Probe{Address: p.Address, Protocol: "https", HTTPHost: p.Host, TLSName: p.SNI, Path: p.Path, Trust: &edge.Material{TrustPEM: p.TrustPEM}})
}
