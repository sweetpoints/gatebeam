package application

import (
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/transaction"
	"sort"
	"strings"
)

// VerifiedPublication is an internal owner contract. The integration coordinator
// holds identity authority first, then GuardPublicationWithin, through the real
// effect and receipt transaction. It is never accepted from an HTTP body.
type VerifiedPublication struct {
	PublishedBase map[string]int64
	Sites         []VerifiedSite
	Targets       []VerifiedTarget
}
type VerifiedSite struct {
	ID       string
	Revision int64
	Config   domain.SiteConfig
}
type VerifiedTarget struct {
	ID       string
	Revision int64
	Config   domain.TargetConfig
}
type publicationRepository interface {
	PublishSite(transaction.Scope, VerifiedSite, []string) error
	PublishTarget(transaction.Scope, VerifiedTarget) error
}

// GuardPublicationWithin takes the final WRITE mode before any graph reads.
func (s *Service) GuardPublicationWithin(sc transaction.Scope) error { return s.repo.WriteLock(sc) }
func (s *Service) CommitVerifiedWithin(sc transaction.Scope, in VerifiedPublication) error {
	if e := s.repo.WriteLock(sc); e != nil {
		return e
	}
	g, e := s.repo.Graph(sc)
	if e != nil {
		return e
	}
	actual := map[string]int64{}
	for _, v := range g.Sites {
		if !v.Deleted {
			actual["site:"+v.ID] = v.PublishedRevision
		}
	}
	for _, v := range g.Targets {
		actual["target:"+v.ID] = v.PublishedRevision
	}
	for k, v := range in.PublishedBase {
		if n, ok := actual[k]; !ok || n != v {
			return domain.ErrConflict
		}
	}
	for k, v := range actual {
		// Every published site is exported; only needed/selected targets are.
		if v > 0 && strings.HasPrefix(k, "site:") {
			if n, ok := in.PublishedBase[k]; !ok || n != v {
				return domain.ErrConflict
			}
		}
	}
	repo, ok := s.repo.(publicationRepository)
	if !ok {
		return domain.ErrUnavailable
	}
	sort.Slice(in.Sites, func(i, j int) bool { return in.Sites[i].ID < in.Sites[j].ID })
	sort.Slice(in.Targets, func(i, j int) bool { return in.Targets[i].ID < in.Targets[j].ID })
	seen := map[string]bool{}
	for _, v := range in.Sites {
		if !domain.ValidID(v.ID) || v.Revision < 1 || seen[v.ID] {
			return domain.ErrInvalid
		}
		seen[v.ID] = true
		if _, ok := in.PublishedBase["site:"+v.ID]; !ok {
			return domain.ErrConflict
		}
		current, e := site(g, v.ID)
		if e != nil {
			return e
		}
		domains := append(append([]string{}, current.Draft.Domains...), v.Config.Domains...)
		if e = repo.PublishSite(sc, v, unique(domains)); e != nil {
			return e
		}
	}
	for _, v := range in.Targets {
		if !domain.ValidID(v.ID) || v.Revision < 1 || seen[v.ID] {
			return domain.ErrInvalid
		}
		seen[v.ID] = true
		if _, ok := in.PublishedBase["target:"+v.ID]; !ok {
			return domain.ErrConflict
		}
		if e = repo.PublishTarget(sc, v); e != nil {
			return e
		}
	}
	return nil
}

// GuardReferencesWithin freezes both draft and published reference sets before
// an owning material context locks or changes referenced resources.
func (s *Service) GuardReferencesWithin(sc transaction.Scope) error { return s.repo.ReadLock(sc) }
