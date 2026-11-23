package runtime

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	"net/netip"
	"strings"
	"sync"
	"time"
)

var ErrRouteVerification = errors.New("post-apply read-only route verification failed")

type RouteResult struct {
	SiteID         string `json:"site_id"`
	SiteRevision   int64  `json:"site_revision"`
	TargetID       string `json:"target_id"`
	TargetRevision int64  `json:"target_revision"`
	Route          string `json:"route"`
	Host           string `json:"host"`
	SNI            string `json:"sni"`
	Path           string `json:"path,omitempty"`
	Outcome        string `json:"outcome"`
	Reason         string `json:"reason,omitempty"`
}
type RouteVerification struct {
	ArtifactID       string        `json:"artifact_id"`
	Version          string        `json:"version"`
	Generation       string        `json:"generation"`
	CheckedAt        time.Time     `json:"checked_at"`
	NativeVerified   bool          `json:"native_verified"`
	BusinessVerified bool          `json:"business_verified"`
	Routes           []RouteResult `json:"routes"`
}
type RouteProbe struct {
	Address         netip.AddrPort
	Host, SNI, Path string
	TrustPEM        []byte
}
type RouteProber interface {
	CheckRoute(context.Context, RouteProbe) error
}
type RouteEvidence interface {
	SaveRouteVerification(context.Context, RouteVerification) error
}
type PostApplyVerifier interface {
	Verify(context.Context, Plan, string) (RouteVerification, error)
}

// RouteVerifier executes only operator-enabled health GET paths through the
// newly applied local listener. It never adds headers or bypasses entry policy.
type RouteVerifier struct {
	Probe    RouteProber
	Evidence RouteEvidence
}

func (v RouteVerifier) Verify(ctx context.Context, plan Plan, artifact string) (RouteVerification, error) {
	report := RouteVerification{ArtifactID: artifact, Version: plan.Snapshot.Version, Generation: plan.Runtime.Generation, NativeVerified: true, BusinessVerified: true, Routes: []RouteResult{}}
	type work struct {
		index int
		probe RouteProbe
	}
	pending := []work{}
	targets := map[string]app.Target{}
	for _, target := range plan.Snapshot.Targets {
		targets[target.ID] = target
	}
	for _, site := range plan.Snapshot.Sites {
		routes := append([]app.Route{{Target: site.Config.DefaultTarget}}, site.Config.Routes...)
		for ri, route := range routes {
			// The compiler omits its synthetic default location when an explicit
			// prefix / owns it. Keep original route indexes for selection checks.
			if ri == 0 {
				suppressed := false
				for _, explicit := range site.Config.Routes {
					if explicit.Match == "prefix" && explicit.Path == "/" {
						suppressed = true
						break
					}
				}
				if suppressed {
					continue
				}
			}
			for _, host := range site.Config.Domains {
				target, exists := targets[route.Target.ID]
				result := RouteResult{SiteID: site.ID, SiteRevision: site.Revision, TargetID: route.Target.ID, TargetRevision: target.Revision, Route: route.Path, Host: host, SNI: host, Outcome: "unavailable"}
				switch {
				case !site.Config.Enabled:
					result.Outcome = "not_applicable"
					result.Reason = "site_disabled"
				case site.Config.Maintenance.Enabled:
					result.Outcome = "not_applicable"
					result.Reason = "maintenance_policy"
				case site.Config.Cloudflare.Mode == "proxied" || site.Config.Cloudflare.RequireOriginPull || (site.Config.ClientVerification.Mode != "" && site.Config.ClientVerification.Mode != "off"):
					result.Outcome = "policy_refused"
					result.Reason = "authorized_entry_identity_unavailable"
				case exists && allMembersUnhealthy(target, plan.Runtime):
					result.Outcome = "not_applicable"
					result.Reason = "all_unhealthy_policy"
				case !exists || !target.Config.Health.Enabled:
					result.Reason = "read_only_probe_not_configured"
				default:
					path := target.Config.Health.Path
					if !canonicalProbePath(path) {
						result.Reason = "read_only_probe_not_configured"
						break
					}
					if route.StripPrefix {
						path = route.Path + strings.TrimPrefix(path, "/")
					}
					if !canonicalProbePath(path) {
						result.Reason = "read_only_probe_unmappable"
						break
					}
					upstreamHost := target.Config.HTTPHost
					if upstreamHost == "" {
						upstreamHost = host
					}
					if target.Config.Health.HTTPHost != "" && target.Config.Health.HTTPHost != upstreamHost {
						result.Reason = "read_only_probe_host_unmappable"
						break
					}
					result.Path = path
					if selectedRoute(site.Config.Routes, path) != ri-1 {
						result.Reason = "read_only_probe_unmappable"
						break
					}
					if site.Config.EntryCertificate == nil {
						result.Reason = "entry_tls_identity_unavailable"
						break
					}
					material, ok := plan.Runtime.Materials[site.Config.EntryCertificate.ID]
					if !ok || material.Revision != site.Config.EntryCertificate.Revision || len(material.CertificatePEM) == 0 {
						result.Reason = "entry_tls_identity_unavailable"
						break
					}
					result.Outcome = "pending"
					pending = append(pending, work{len(report.Routes), RouteProbe{Address: netip.MustParseAddrPort("127.0.0.1:8443"), Host: host, SNI: host, Path: path, TrustPEM: material.CertificatePEM}})
				}
				report.Routes = append(report.Routes, result)
			}
		}
	}
	// All routes receive an outcome. No size-based truncation or successful
	// partial result: exhausting this shared budget is a verification failure.
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	queue := make(chan work)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for w := range queue {
				result := &report.Routes[w.index]
				if probeCtx.Err() != nil {
					result.Outcome = "degraded"
					result.Reason = "verification_budget_exhausted"
					continue
				}
				if v.Probe == nil {
					result.Outcome = "degraded"
					result.Reason = "probe_unavailable"
					continue
				}
				err := v.Probe.CheckRoute(probeCtx, w.probe)
				// The verifier owns this budget even if an adapter returns nil
				// after its context expires. Headers alone are not success.
				switch {
				case probeCtx.Err() != nil:
					result.Outcome = "degraded"
					result.Reason = "verification_budget_exhausted"
				case err != nil:
					result.Outcome = "degraded"
					result.Reason = "tls_or_route_probe_failed"
				default:
					result.Outcome = "verified"
				}
			}
		}()
	}
	for _, w := range pending {
		queue <- w
	}
	close(queue)
	group.Wait()
	if len(report.Routes) == 0 {
		report.BusinessVerified = false
	}
	var err error
	for _, result := range report.Routes {
		if result.Outcome != "verified" {
			report.BusinessVerified = false
		}
		if result.Outcome == "degraded" {
			err = ErrRouteVerification
		}
	}
	report.CheckedAt = time.Now().UTC()
	if v.Evidence == nil {
		return report, errors.Join(err, errors.New("route evidence unavailable"))
	}
	// Preserve failed/timeout evidence even after the probe context expires.
	saveCtx, done := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer done()
	return report, errors.Join(err, v.Evidence.SaveRouteVerification(saveCtx, report))
}
func selectedRoute(routes []app.Route, path string) int {
	selected := -1
	length := -1
	for i, route := range routes {
		if route.Match == "exact" && path == route.Path {
			return i
		}
		if route.Match == "prefix" && strings.HasPrefix(path, route.Path) && len(route.Path) > length {
			selected = i
			length = len(route.Path)
		}
	}
	return selected
}

func allMembersUnhealthy(target app.Target, state RuntimeState) bool {
	health, ok := state.Health[target.ID]
	if !ok || !target.Config.Health.Enabled || health.TargetRevision != target.Revision {
		return false
	}
	count := 0
	for _, member := range target.Config.Members {
		addresses := state.Resolved[target.ID+"/"+member.Address].Addresses
		if address, err := netip.ParseAddr(member.Address); err == nil {
			addresses = []netip.Addr{address}
		}
		if len(addresses) == 0 {
			return false
		}
		for _, address := range addresses {
			count++
			if !health.Unhealthy[netip.AddrPortFrom(address, uint16(member.Port)).String()] {
				return false
			}
		}
	}
	return count > 0
}

// Nginx normalizes URI escapes, dot segments and repeated slashes before route
// selection. Refuse ambiguous paths instead of authorizing a different route.
func canonicalProbePath(path string) bool {
	if len(path) == 0 || len(path) > 2048 || path[0] != '/' || strings.ContainsAny(path, "%?#\\\x00\r\n") || strings.Contains(path, "//") {
		return false
	}
	for _, part := range strings.Split(path, "/") {
		if part == "." || part == ".." {
			return false
		}
	}
	return true
}
