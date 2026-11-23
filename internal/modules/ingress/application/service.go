package application

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"sort"
	"strconv"
	"strings"
	"time"
)

var ErrDenied = errors.New("ingress permission denied")

type Service struct {
	tx    transaction.Runner
	repo  Repository
	auth  Authorizer
	audit Audit
	ids   IDs
}

func New(tx transaction.Runner, r Repository, a Authorizer, w Audit, ids IDs) *Service {
	return &Service{tx, r, a, w, ids}
}
func (s *Service) within(ctx context.Context, a ActorRef, write bool, fn func(transaction.Scope) error) error {
	if sc, ok := ctx.Value(mutationScopeKey{}).(transaction.Scope); ok {
		return fn(sc)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.auth.GuardWithin(sc, a); e != nil {
			return e
		}
		var e error
		if write {
			e = s.repo.WriteLock(sc)
		} else {
			e = s.repo.ReadLock(sc)
		}
		if e != nil {
			return e
		}
		return fn(sc)
	})
}
func (s *Service) event(sc transaction.Scope, a ActorRef, action, id string) error {
	eid, e := s.ids.NewID()
	if e != nil {
		return e
	}
	v, e := json.Marshal(struct {
		ResourceID string `json:"resource_id"`
	}{id})
	if e != nil {
		return e
	}
	return s.audit.Append(sc, audit.Event{ID: eid, ActorID: a.UserID, Action: action, Payload: v})
}
func (s *Service) require(sc transaction.Scope, a ActorRef, action string, ids []string) error {
	ids = unique(ids)
	if len(ids) == 0 {
		return s.auth.RequireWithin(sc, a, "manage", nil)
	}
	for i := 0; i < len(ids); i += 100 {
		end := i + 100
		if end > len(ids) {
			end = len(ids)
		}
		if e := s.auth.RequireWithin(sc, a, action, ids[i:end]); e != nil {
			return e
		}
	}
	return nil
}
func unique(v []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range v {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
func site(g Graph, id string) (domain.Site, error) {
	for _, v := range g.Sites {
		if v.ID == id && !v.Deleted {
			return v, nil
		}
	}
	return domain.Site{}, domain.ErrNotFound
}
func target(g Graph, id string) (domain.TargetGroup, error) {
	for _, v := range g.Targets {
		if v.ID == id {
			return v, nil
		}
	}
	return domain.TargetGroup{}, domain.ErrNotFound
}
func group(g Graph, id string) (domain.SiteGroup, error) {
	for _, v := range g.Groups {
		if v.ID == id {
			return v, nil
		}
	}
	return domain.SiteGroup{}, domain.ErrNotFound
}
func validGroups(g Graph, ids []string) error {
	if len(ids) > 100 {
		return domain.ErrInvalid
	}
	if _, e := domain.IDs(ids); e != nil {
		return e
	}
	for _, id := range ids {
		if _, e := group(g, id); e != nil {
			return e
		}
	}
	return nil
}
func refsValid(g Graph, c domain.SiteConfig) error {
	for _, r := range c.TargetRefs() {
		if _, e := target(g, r.ID); e != nil {
			return domain.ErrInvalid
		}
	}
	return nil
}
func (s *Service) CreateSite(ctx context.Context, a ActorRef, in CreateSite) (domain.Site, error) {
	var out domain.Site
	e := s.within(ctx, a, true, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		if e = validGroups(g, in.GroupIDs); e != nil {
			return e
		}
		if len(in.GroupIDs) == 0 {
			e = s.require(sc, a, "manage", nil)
		} else {
			e = s.auth.RequireGroupCreateWithin(sc, a, in.GroupIDs)
		}
		if e != nil {
			return e
		}
		name, e := domain.Name(in.Name)
		if e != nil {
			return e
		}
		if e = in.Config.Normalize(); e != nil {
			return e
		}
		if e = s.repo.ValidateSite(in.Config); e != nil {
			return e
		}
		if e = refsValid(g, in.Config); e != nil {
			return e
		}
		id, e := s.ids.NewID()
		if e != nil {
			return e
		}
		out = domain.Site{ID: id, Name: name, GroupIDs: in.GroupIDs, Revision: 1, Draft: in.Config}
		if e = s.repo.SaveSite(sc, out, 0); e != nil {
			return e
		}
		return s.event(sc, a, "ingress.site.created", id)
	})
	if e != nil {
		return domain.Site{}, e
	}
	return out, nil
}
func (s *Service) SaveDraft(ctx context.Context, a ActorRef, in Draft, expected int64) (Revision, error) {
	var out Revision
	if !domain.ValidID(in.SiteID) || expected < 1 {
		return out, domain.ErrInvalid
	}
	e := s.within(ctx, a, true, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		v, e := site(g, in.SiteID)
		if e != nil {
			return ErrDenied
		}
		if e = s.require(sc, a, "edit", []string{v.ID}); e != nil {
			return e
		}
		if v.Revision != expected {
			return domain.ErrConflict
		}
		if e = in.Config.Normalize(); e != nil {
			return e
		}
		if e = s.repo.ValidateSite(in.Config); e != nil {
			return e
		}
		if e = refsValid(g, in.Config); e != nil {
			return e
		}
		if e = v.ReviseDraft(in.Config, expected); e != nil {
			return e
		}
		if e = s.repo.SaveSite(sc, v, expected); e != nil {
			return e
		}
		out = Revision{v.ID, v.Revision}
		return s.event(sc, a, "ingress.site.draft_saved", v.ID)
	})
	return out, e
}
func (s *Service) Site(ctx context.Context, a ActorRef, id string) (domain.Site, error) {
	var out domain.Site
	if !domain.ValidID(id) {
		return out, domain.ErrInvalid
	}
	e := s.within(ctx, a, false, func(sc transaction.Scope) error {
		if e := s.require(sc, a, "view", []string{id}); e != nil {
			return e
		}
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		out, e = site(g, id)
		return e
	})
	if e != nil {
		return domain.Site{}, e
	}
	return out, nil
}
func (s *Service) Sites(ctx context.Context, a ActorRef, limit, offset int) ([]domain.Site, error) {
	out := []domain.Site{}
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return nil, domain.ErrInvalid
	}
	e := s.within(ctx, a, false, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		visible := 0
		for _, v := range g.Sites {
			if v.Deleted {
				continue
			}
			if e = s.require(sc, a, "view", []string{v.ID}); e != nil {
				if errors.Is(e, ErrDenied) {
					continue
				}
				return e
			}
			if visible >= offset && len(out) < limit {
				out = append(out, v)
			}
			visible++
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return out, nil
}
func (s *Service) SetGroups(ctx context.Context, a ActorRef, id string, groups []string, expected int64) error {
	if !domain.ValidID(id) || expected < 1 {
		return domain.ErrInvalid
	}
	return s.within(ctx, a, true, func(sc transaction.Scope) error {
		if e := s.require(sc, a, "manage", nil); e != nil {
			return e
		}
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		v, e := site(g, id)
		if e != nil {
			return e
		}
		if v.Revision != expected {
			return domain.ErrConflict
		}
		if e = validGroups(g, groups); e != nil {
			return e
		}
		if e = v.MoveTo(groups, expected); e != nil {
			return e
		}
		if e = s.repo.SaveSite(sc, v, expected); e != nil {
			return e
		}
		return s.event(sc, a, "ingress.site.groups_changed", id)
	})
}
func (s *Service) DeleteSite(ctx context.Context, a ActorRef, id string, expected int64) error {
	if !domain.ValidID(id) || expected < 1 {
		return domain.ErrInvalid
	}
	return s.within(ctx, a, true, func(sc transaction.Scope) error {
		if e := s.require(sc, a, "edit", []string{id}); e != nil {
			return e
		}
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		v, e := site(g, id)
		if e != nil {
			return ErrDenied
		}
		if v.Revision != expected {
			return domain.ErrConflict
		}
		if e = v.Remove(expected); e != nil {
			return e
		}
		if e = s.repo.DeleteSite(sc, id, expected); e != nil {
			return e
		}
		return s.event(sc, a, "ingress.site.deleted", id)
	})
}
func affected(g Graph, id string) []string {
	targets := map[string]bool{}
	for _, t := range g.Targets {
		if t.ID == id {
			targets[t.ID] = true
		}
		configs := []domain.TargetConfig{t.Config}
		if t.Published != nil {
			configs = append(configs, *t.Published)
		}
		for _, c := range configs {
			for _, m := range c.Materials() {
				if m.ID == id {
					targets[t.ID] = true
				}
			}
		}
	}
	out := []string{}
	for _, v := range g.Sites {
		if v.Deleted {
			continue
		}
		found := false
		configs := []domain.SiteConfig{v.Draft}
		if v.Published != nil {
			configs = append(configs, *v.Published)
		}
		for _, c := range configs {
			for _, r := range c.TargetRefs() {
				if r.ID == id || targets[r.ID] {
					found = true
				}
			}
			for _, r := range c.Materials() {
				if r.ID == id {
					found = true
				}
			}
		}
		if found {
			out = append(out, v.ID)
		}
	}
	return unique(out)
}

// AffectedSites is an internal coordination query. It is never exposed through
// REST. User-facing calls reauthorize the complete result before returning data.
func (s *Service) AffectedSites(ctx context.Context, resourceID string) ([]string, error) {
	if !domain.ValidID(resourceID) {
		return nil, domain.ErrInvalid
	}
	var out []string
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	e := s.tx.Within(ctx, func(sc transaction.Scope) error {
		var e error
		out, e = s.AffectedSitesWithin(sc, resourceID)
		return e
	})
	return out, e
}

// Caller must already hold the identity watermark. Graph read never upgrades.
func (s *Service) AffectedSitesWithin(sc transaction.Scope, id string) ([]string, error) {
	if e := s.repo.ReadLock(sc); e != nil {
		return nil, e
	}
	g, e := s.repo.Graph(sc)
	if e != nil {
		return nil, e
	}
	return affected(g, id), nil
}
func (s *Service) SaveTarget(ctx context.Context, a ActorRef, in domain.TargetGroup, expected int64) (domain.TargetGroup, error) {
	var out domain.TargetGroup
	if expected < 0 {
		return out, domain.ErrInvalid
	}
	e := s.within(ctx, a, true, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		if in.ID == "" {
			if expected != 0 {
				return domain.ErrInvalid
			}
			if e = s.require(sc, a, "manage", nil); e != nil {
				return e
			}
			in.ID, e = s.ids.NewID()
			if e != nil {
				return e
			}
		} else {
			if !domain.ValidID(in.ID) || expected < 1 {
				return domain.ErrInvalid
			}
			old, e := target(g, in.ID)
			if e != nil {
				return ErrDenied
			}
			if e = s.require(sc, a, "edit", affected(g, in.ID)); e != nil {
				return e
			}
			if old.Revision != expected {
				return domain.ErrConflict
			}
			in.PublishedRevision = old.PublishedRevision
			in.Published = old.Published
		}
		if e = in.Config.Normalize(); e != nil {
			return e
		}
		if e = s.repo.ValidateTarget(in.Config); e != nil {
			return e
		}
		if expected == 0 {
			in.Published = nil
			in.PublishedRevision = 0
		}
		in.Revision = expected
		if e = in.Revise(in.Config, expected); e != nil {
			return e
		}
		if e = s.repo.SaveTarget(sc, in, expected); e != nil {
			return e
		}
		out = in
		return s.event(sc, a, "ingress.target.draft_saved", in.ID)
	})
	if e != nil {
		return domain.TargetGroup{}, e
	}
	return out, nil
}
func (s *Service) Target(ctx context.Context, a ActorRef, id string) (domain.TargetGroup, error) {
	var out domain.TargetGroup
	if !domain.ValidID(id) {
		return out, domain.ErrInvalid
	}
	e := s.within(ctx, a, false, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		if e = s.require(sc, a, "view", affected(g, id)); e != nil {
			return e
		}
		out, e = target(g, id)
		return e
	})
	if e != nil {
		return domain.TargetGroup{}, e
	}
	return out, nil
}
func (s *Service) Targets(ctx context.Context, a ActorRef, limit, offset int) ([]domain.TargetGroup, error) {
	out := []domain.TargetGroup{}
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return nil, domain.ErrInvalid
	}
	e := s.within(ctx, a, false, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		visible := 0
		for _, v := range g.Targets {
			if e = s.require(sc, a, "view", affected(g, v.ID)); e != nil {
				if errors.Is(e, ErrDenied) {
					continue
				}
				return e
			}
			if visible >= offset && len(out) < limit {
				out = append(out, v)
			}
			visible++
		}
		return nil
	})
	return out, e
}
func (s *Service) DeleteTarget(ctx context.Context, a ActorRef, id string, expected int64) error {
	if !domain.ValidID(id) || expected < 1 {
		return domain.ErrInvalid
	}
	return s.within(ctx, a, true, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		refs := affected(g, id)
		if e = s.require(sc, a, "edit", refs); e != nil {
			return e
		}
		v, e := target(g, id)
		if e != nil {
			return ErrDenied
		}
		if v.Revision != expected {
			return domain.ErrConflict
		}
		if len(refs) > 0 || v.Published != nil {
			return domain.ErrReferenced
		}
		if e = s.repo.DeleteTarget(sc, id, expected); e != nil {
			return e
		}
		return s.event(sc, a, "ingress.target.deleted", id)
	})
}
func (s *Service) SaveGroup(ctx context.Context, a ActorRef, in domain.SiteGroup, expected int64) (domain.SiteGroup, error) {
	var out domain.SiteGroup
	e := s.within(ctx, a, true, func(sc transaction.Scope) error {
		if e := s.require(sc, a, "manage", nil); e != nil {
			return e
		}
		if expected < 0 {
			return domain.ErrInvalid
		}
		if in.ID == "" {
			if expected != 0 {
				return domain.ErrInvalid
			}
			var e error
			in.ID, e = s.ids.NewID()
			if e != nil {
				return e
			}
		} else if expected == 0 {
			return domain.ErrInvalid
		}
		if e := in.Normalize(); e != nil {
			return e
		}
		in.Revision = expected + 1
		if e := s.repo.SaveGroup(sc, in, expected); e != nil {
			return e
		}
		out = in
		return s.event(sc, a, "ingress.group.saved", in.ID)
	})
	return out, e
}
func (s *Service) DeleteGroup(ctx context.Context, a ActorRef, id string, expected int64) error {
	if !domain.ValidID(id) || expected < 1 {
		return domain.ErrInvalid
	}
	return s.within(ctx, a, true, func(sc transaction.Scope) error {
		if e := s.require(sc, a, "manage", nil); e != nil {
			return e
		}
		if e := s.repo.DeleteGroup(sc, id, expected); e != nil {
			return e
		}
		return s.event(sc, a, "ingress.group.deleted", id)
	})
}
func (s *Service) Groups(ctx context.Context, a ActorRef, limit, offset int) ([]domain.SiteGroup, error) {
	out := []domain.SiteGroup{}
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return nil, domain.ErrInvalid
	}
	e := s.within(ctx, a, false, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		visible := 0
		visibleGroups := map[string]bool{}
		for _, v := range g.Sites {
			if v.Deleted {
				continue
			}
			e := s.require(sc, a, "view", []string{v.ID})
			if e != nil {
				if errors.Is(e, ErrDenied) {
					continue
				}
				return e
			}
			for _, id := range v.GroupIDs {
				visibleGroups[id] = true
			}
		}
		for _, v := range g.Groups {
			if !visibleGroups[v.ID] {
				if e = s.auth.RequireGroupCreateWithin(sc, a, []string{v.ID}); e != nil {
					if errors.Is(e, ErrDenied) {
						continue
					}
					return e
				}
			}
			if visible >= offset && len(out) < limit {
				out = append(out, v)
			}
			visible++
		}
		return nil
	})
	return out, e
}

// SiteGroupsWithin is the identity consumer catalog: unknown IDs fail closed;
// known ungrouped sites have an empty, successful membership result.
func (s *Service) SiteGroupsWithin(sc transaction.Scope, id string) ([]string, error) {
	if !domain.ValidID(id) {
		return nil, domain.ErrNotFound
	}
	if e := s.repo.ReadLock(sc); e != nil {
		return nil, e
	}
	// Authorization needs current membership, not every configuration revision.
	// Loading the whole graph for every member makes shared-resource checks
	// quadratic in the number of sites inside the same bounded transaction.
	return s.repo.SiteGroups(sc, id)
}
func (s *Service) GroupExistsWithin(sc transaction.Scope, id string) error {
	if !domain.ValidID(id) {
		return domain.ErrNotFound
	}
	if e := s.repo.ReadLock(sc); e != nil {
		return e
	}
	g, e := s.repo.Graph(sc)
	if e != nil {
		return e
	}
	_, e = group(g, id)
	return e
}

// ReadForReleaseWithin freezes only the ingress graph. The trusted I2 coordinator
// acquires identity first and authorizes AuthorizationSiteIDs in the SAME Scope.
// No head advances here. Expected typed keys select drafts explicitly.
func (s *Service) ReadForReleaseWithin(sc transaction.Scope, siteIDs []string, expected map[string]int64) (ReleaseInputs, error) {
	return s.readForReleaseWithin(sc, siteIDs, expected, nil)
}

// ReadHistoricalForReleaseWithin guards CURRENT heads while exporting explicitly
// selected historical logical content. Current memberships and full reference
// authority still come from the current graph; no historical ACL is restored.
func (s *Service) ReadHistoricalForReleaseWithin(sc transaction.Scope, siteIDs []string, expected map[string]int64, chosen RevisionExport) (ReleaseInputs, error) {
	return s.readForReleaseWithin(sc, siteIDs, expected, &chosen)
}
func (s *Service) readForReleaseWithin(sc transaction.Scope, siteIDs []string, expected map[string]int64, historical *RevisionExport) (ReleaseInputs, error) {
	var out ReleaseInputs
	if e := s.repo.ReadLock(sc); e != nil {
		return out, e
	}
	g, e := s.repo.Graph(sc)
	if e != nil {
		return out, e
	}
	selected, e := domain.IDs(siteIDs)
	if e != nil {
		return out, e
	}
	selectedSet := map[string]bool{}
	for _, id := range selected {
		v, e := site(g, id)
		if e != nil {
			return out, e
		}
		if expected["site:"+id] != v.Revision {
			return out, domain.ErrConflict
		}
		selectedSet[id] = true
	}
	targets := []string{}
	for key, n := range expected {
		if strings.HasPrefix(key, "site:") {
			if !selectedSet[strings.TrimPrefix(key, "site:")] {
				return out, domain.ErrInvalid
			}
			continue
		}
		if !strings.HasPrefix(key, "target:") {
			return out, domain.ErrInvalid
		}
		id := strings.TrimPrefix(key, "target:")
		t, e := target(g, id)
		if e != nil {
			return out, e
		}
		if n != t.Revision {
			return out, domain.ErrConflict
		}
		targets = append(targets, id)
	}
	targets = unique(targets)
	authority := append([]string{}, selected...)
	for _, id := range targets {
		authority = append(authority, affected(g, id)...)
	}
	out = ReleaseInputs{Export: RevisionExport{Version: "ingress/v1", Sites: []Site{}, Targets: []TargetGroup{}, Certificates: []CertificateRef{}, Trusts: []TrustRef{}}, AuthorizationSiteIDs: unique(authority), SelectedSiteIDs: selected, SelectedTargetIDs: targets, Expected: map[string]int64{}}
	for k, v := range expected {
		out.Expected[k] = v
	}
	if historical != nil {
		// Historical content must not reclaim a domain held by ANY current
		// draft or published site, including an unselected draft-only site.
		for _, old := range historical.Sites {
			if !selectedSet[old.ID] || old.Draft == nil {
				continue
			}
			names := map[string]bool{}
			for _, name := range old.Draft.Domains {
				names[name] = true
			}
			for _, current := range g.Sites {
				if current.Deleted || current.ID == old.ID {
					continue
				}
				configs := []domain.SiteConfig{current.Draft}
				if current.Published != nil {
					configs = append(configs, *current.Published)
				}
				for _, cfg := range configs {
					for _, name := range cfg.Domains {
						if names[name] {
							return out, domain.ErrConflict
						}
					}
				}
			}
		}
		// Replace only chosen content in a private graph copy. affected() MUST
		// continue using the original live graph to include all current refs.
		for _, id := range selected {
			found := false
			for _, v := range historical.Sites {
				if v.ID == id && v.Draft != nil {
					found = true
				}
			}
			if !found {
				return out, domain.ErrInvalid
			}
		}
		for _, id := range targets {
			found := false
			for _, v := range historical.Targets {
				if v.ID == id {
					found = true
				}
			}
			if !found {
				return out, domain.ErrInvalid
			}
		}
	}
	needed := map[string]bool{}
	for _, v := range g.Sites {
		if v.Deleted {
			continue
		}
		if v.Published == nil && !selectedSet[v.ID] {
			continue
		}
		if historical != nil && selectedSet[v.ID] {
			for _, old := range historical.Sites {
				if old.ID == v.ID {
					v.Draft = old.Draft.Clone()
				}
			}
		}
		exported := Site{ID: v.ID, Name: v.Name, GroupIDs: v.GroupIDs, PublishedRevision: v.PublishedRevision, Published: v.Published}
		if v.Published != nil {
			c := *v.Published
			if e = c.Normalize(); e != nil {
				return ReleaseInputs{}, e
			}
			if e = s.repo.ValidateSite(c); e != nil {
				return ReleaseInputs{}, e
			}
			if e = refsValid(g, c); e != nil {
				return ReleaseInputs{}, e
			}
			for _, r := range c.TargetRefs() {
				needed[r.ID] = true
			}
		}
		if selectedSet[v.ID] {
			if e = v.Draft.Normalize(); e != nil {
				return ReleaseInputs{}, e
			}
			if e = s.repo.ValidateSite(v.Draft); e != nil {
				return ReleaseInputs{}, e
			}
			if e = refsValid(g, v.Draft); e != nil {
				return ReleaseInputs{}, e
			}
			exported.Revision = v.Revision
			exported.Draft = &v.Draft
			for _, r := range v.Draft.TargetRefs() {
				needed[r.ID] = true
			}
			for _, r := range v.Draft.TargetRefs() {
				authority = append(authority, affected(g, r.ID)...)
			}
			for _, m := range v.Draft.Materials() {
				authority = append(authority, affected(g, m.ID)...)
			}
		}
		out.Export.Sites = append(out.Export.Sites, exported)
	}
	for _, id := range targets {
		needed[id] = true
	}
	for _, t := range g.Targets {
		if !needed[t.ID] {
			continue
		}
		if historical != nil {
			for _, selectedID := range targets {
				if selectedID == t.ID {
					for _, old := range historical.Targets {
						if old.ID == t.ID {
							t.Config = old.Config.Clone()
						}
					}
				}
			}
		}
		if e = t.Config.Normalize(); e != nil {
			return ReleaseInputs{}, e
		}
		if e = s.repo.ValidateTarget(t.Config); e != nil {
			return ReleaseInputs{}, e
		}
		if t.Published != nil {
			c := *t.Published
			if e = c.Normalize(); e != nil {
				return ReleaseInputs{}, e
			}
		}
		relevant := false
		for _, v := range out.Export.Sites {
			if v.Draft != nil {
				for _, r := range v.Draft.TargetRefs() {
					if r.ID == t.ID {
						relevant = true
					}
				}
			}
		}
		chosen := t.Published
		for _, selectedID := range targets {
			if selectedID == t.ID {
				relevant = true
				c := t.Config
				chosen = &c
			}
		}
		if relevant && chosen != nil {
			for _, m := range chosen.Materials() {
				authority = append(authority, affected(g, m.ID)...)
			}
		}
		out.Export.Targets = append(out.Export.Targets, TargetGroup(t))
	}
	out.AuthorizationSiteIDs = unique(authority)
	collectMaterials(&out.Export)
	return out, nil
}
func collectMaterials(out *RevisionExport) {
	certs := map[string]domain.MaterialRef{}
	trusts := map[string]domain.MaterialRef{}
	for _, s := range out.Sites {
		configs := []domain.SiteConfig{}
		if s.Draft != nil {
			configs = append(configs, *s.Draft)
		}
		if s.Published != nil {
			configs = append(configs, *s.Published)
		}
		for _, c := range configs {
			if c.EntryCertificate != nil {
				certs[materialKey(*c.EntryCertificate)] = *c.EntryCertificate
			}
			if c.ClientVerification.Trust != nil {
				trusts[materialKey(*c.ClientVerification.Trust)] = *c.ClientVerification.Trust
			}
		}
	}
	for _, t := range out.Targets {
		configs := []domain.TargetConfig{t.Config}
		if t.Published != nil {
			configs = append(configs, *t.Published)
		}
		for _, c := range configs {
			if c.ClientCertificate != nil {
				certs[materialKey(*c.ClientCertificate)] = *c.ClientCertificate
			}
			if c.Trust != nil {
				trusts[materialKey(*c.Trust)] = *c.Trust
			}
		}
	}
	ids := []string{}
	for id := range certs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out.Certificates = append(out.Certificates, CertificateRef(certs[id]))
	}
	ids = nil
	for id := range trusts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		out.Trusts = append(out.Trusts, TrustRef(trusts[id]))
	}
}

func materialKey(v domain.MaterialRef) string { return v.ID + ":" + strconv.FormatInt(v.Revision, 10) }
