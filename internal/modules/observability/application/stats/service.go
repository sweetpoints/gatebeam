package stats

import (
	"context"
	"gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/platform/transaction"
	"strings"
	"time"
)

var ErrDenied = domain.ErrDenied
var ErrInvalid = domain.ErrInvalid
var ErrCapacity = domain.ErrCapacity

type ActorRef struct {
	UserID                       string
	AuthVersion                  int64
	CredentialKind, CredentialID string
}
type Filter struct {
	SiteIDs       []string
	From, To      time.Time
	Route, Method string
	ConfigID      string
	StatusClass   int
}
type Series struct {
	Buckets              []domain.Bucket
	Count, Micros, Bytes int64
	Histogram            domain.Histogram
	P50Micros, P95Micros int64
	IngestedAt           time.Time
	Approximate          bool
}
type Security interface {
	RequireWithin(transaction.Scope, ActorRef, []string) error
}
type Repository interface {
	QueryWithin(transaction.Scope, Filter) ([]domain.Bucket, time.Time, error)
}
type Service struct {
	tx       transaction.Runner
	security Security
	repo     Repository
}

func New(tx transaction.Runner, s Security, r Repository) *Service { return &Service{tx, s, r} }
func (s *Service) Query(ctx context.Context, a ActorRef, f Filter) (Series, error) {
	if len(f.SiteIDs) < 1 || len(f.SiteIDs) > 100 || !f.From.Before(f.To) || f.To.Sub(f.From) > 24*time.Hour || f.From.Second() != 0 || f.From.Nanosecond() != 0 || f.To.Second() != 0 || f.To.Nanosecond() != 0 || f.Route != "" && !domain.ValidRoute(f.Route) || f.Method != "" && !domain.ValidMethod(f.Method) || f.StatusClass < 0 || f.StatusClass > 5 || f.ConfigID != "" && (len(f.ConfigID) != 64 || strings.Trim(f.ConfigID, "0123456789abcdef") != "") {
		return Series{}, domain.ErrInvalid
	}
	for _, id := range f.SiteIDs {
		if !domain.ValidSite(id) {
			return Series{}, domain.ErrInvalid
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out := Series{Approximate: true}
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.security.RequireWithin(sc, a, f.SiteIDs); e != nil {
			return e
		}
		var e error
		out.Buckets, out.IngestedAt, e = s.repo.QueryWithin(sc, f)
		return e
	})
	if e != nil {
		return Series{}, e
	}
	for _, b := range out.Buckets {
		out.Count += b.Count
		out.Micros += b.Micros
		out.Bytes += b.Bytes
		for i, v := range b.Histogram {
			out.Histogram[i] += v
		}
	}
	out.P50Micros = out.Histogram.Percentile(.5)
	out.P95Micros = out.Histogram.Percentile(.95)
	return out, nil
}
