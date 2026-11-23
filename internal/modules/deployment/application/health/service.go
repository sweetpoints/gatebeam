// Package health samples only immutable release targets. Its repository rejects
// stale publication/revision, resolution, member identity and sequence tokens.
package health

import (
	"context"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"net/netip"
	"sync"
	"time"
)

type Timing struct {
	Interval, Timeout   time.Duration
	Failures, Successes int
}

func Policy(p app.HealthPolicy) Timing {
	out := Timing{5 * time.Second, 2 * time.Second, 3, 2}
	if p.IntervalSeconds > 0 && p.IntervalSeconds <= 3600 {
		out.Interval = time.Duration(p.IntervalSeconds) * time.Second
	}
	if p.TimeoutSeconds > 0 && p.TimeoutSeconds <= 60 {
		out.Timeout = time.Duration(p.TimeoutSeconds) * time.Second
	}
	if p.UnhealthyThreshold > 0 && p.UnhealthyThreshold <= 100 {
		out.Failures = p.UnhealthyThreshold
	}
	if p.HealthyThreshold > 0 && p.HealthyThreshold <= 100 {
		out.Successes = p.HealthyThreshold
	}
	return out
}

type Work struct {
	ReleaseID string
	Target    app.Target
	Runtime   edge.RuntimeState
	Sequence  int64
	Token     string
}
type Sample struct {
	Endpoint, Identity string
	Healthy            bool
}
type Update struct {
	Work      Work
	Sequence  int64
	Resolved  map[string][]netip.Addr
	Results   []Sample
	CheckedAt time.Time
}
type Transition struct {
	Changed    bool   `json:"changed"`
	Ignored    bool   `json:"ignored"`
	Revision   int64  `json:"revision"`
	Generation string `json:"generation"`
}
type Repository interface {
	Load(context.Context, string, int64) (Work, error)
	Commit(context.Context, Update) (Transition, error)
}
type Resolver interface {
	Resolve(context.Context, app.Target) (map[string][]netip.Addr, error)
}
type Probe struct {
	Address                           netip.AddrPort
	Protocol, HTTPHost, TLSName, Path string
	TLSServerNameMode                 string
	Trust, ClientCertificate          *edge.Material
}
type Prober interface {
	Check(context.Context, Probe) error
}
type Service struct {
	repo     Repository
	resolver Resolver
	probe    Prober
}

func New(r Repository, d Resolver, p Prober) *Service { return &Service{r, d, p} }
func (s *Service) Check(ctx context.Context, groupID string, revision int64) (Transition, error) {
	ctx, cancel := context.WithTimeout(ctx, domain.MaxHealthBudget)
	defer cancel()
	w, e := s.repo.Load(ctx, groupID, revision)
	if e != nil {
		return Transition{}, e
	}
	if w.Target.ID != groupID || w.Target.Revision != revision {
		return Transition{Ignored: true}, nil
	}
	resolved, e := s.resolver.Resolve(ctx, w.Target)
	if e != nil {
		if recorder, ok := s.repo.(interface {
			DNSFailure(context.Context, Work) error
		}); ok {
			receipt, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer stop()
			if recordError := recorder.DNSFailure(receipt, w); recordError != nil {
				return Transition{}, recordError
			}
		}
		return Transition{}, e
	}
	u := Update{Work: w, Sequence: w.Sequence + 1, Resolved: resolved, CheckedAt: time.Now()}
	p := Policy(w.Target.Config.Health)
	budget, e := Budget(w.Target, resolved)
	if e != nil {
		return Transition{}, e
	}
	ctx, finish := context.WithTimeout(ctx, budget)
	defer finish()
	probes := []Probe{}
	for _, m := range w.Target.Config.Members {
		ips := resolved[m.Address]
		if len(ips) == 0 || len(ips) > 100 {
			return Transition{}, domain.ErrInvalid
		}
		for _, ip := range ips {
			if !w.Target.Config.Health.Enabled {
				continue
			}
			c := w.Target.Config
			host := c.Health.HTTPHost
			if host == "" {
				host = c.HTTPHost
			}
			if host == "" {
				host = m.Address
			}
			name := m.TLSName
			if name == "" {
				name = m.Address
			}
			if c.TLSNameMode == "fixed" {
				name = c.TLSName
			}
			path := c.Health.Path
			if path == "" {
				path = "/"
			}
			probe := Probe{Address: netip.AddrPortFrom(ip, uint16(m.Port)), Protocol: c.Protocol, HTTPHost: host, TLSName: name, Path: path}
			material := func(ref *app.MaterialRef) (*edge.Material, error) {
				if ref == nil {
					return nil, nil
				}
				v, ok := w.Runtime.Materials[ref.ID]
				if !ok || v.Revision != ref.Revision {
					return nil, domain.ErrUnavailable
				}
				return &v, nil
			}
			if c.Protocol == "https" {
				probe.TLSServerNameMode = c.TLSServerNameMode
				probe.Trust, e = material(c.Trust)
				if e != nil {
					return Transition{}, e
				}
				if probe.Trust == nil {
					return Transition{}, domain.ErrUnavailable
				}
				probe.ClientCertificate, e = material(c.ClientCertificate)
				if e != nil {
					return Transition{}, e
				}
			}
			probes = append(probes, probe)
			u.Results = append(u.Results, Sample{Endpoint: probe.Address.String(), Identity: m.Address + "/" + name})
		}
	}
	// Eight independent one-shot probes at a time. A dead endpoint cannot
	// serialize every other member; cancellation joins all workers before return.
	queue := make(chan int, len(probes))
	for i := range probes {
		queue <- i
	}
	close(queue)
	var wg sync.WaitGroup
	for n := 0; n < domain.ProbeConcurrency && n < len(probes); n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range queue {
				if ctx.Err() != nil {
					return
				}
				probe := probes[i]
				check, done := context.WithTimeout(ctx, p.Timeout)
				e := s.probe.Check(check, probe)
				done()
				// Member identity comes from the immutable configured address, separately
				// from the resolved connect address. Match the prepared probe by stable order.
				u.Results[i].Healthy = e == nil
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return Transition{}, ctx.Err()
	}
	return s.repo.Commit(ctx, u)
}

func Budget(target app.Target, resolved map[string][]netip.Addr) (time.Duration, error) {
	count := 0
	if target.Config.Health.Enabled {
		for _, m := range target.Config.Members {
			count += len(resolved[m.Address])
		}
	}
	return domain.HealthBudget(count, Policy(target.Config.Health).Timeout)
}
