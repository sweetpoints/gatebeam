// Package publication coordinates owner application contracts in one transaction.
package publication

import (
	"context"
	"encoding/json"
	"errors"
	deploy "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/domain"
	identity "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	ingress "gatebeam/internal/modules/ingress/application"
	ingressdomain "gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/transaction"
	"sort"
	"time"
)

var ErrDenied = errors.New("publication permission denied")

type ActorRef struct {
	UserID                       string
	AuthVersion                  int64
	CredentialKind, CredentialID string
}
type CandidateView struct {
	NodeProgress    *nodes.Summary           `json:"node_progress,omitempty"`
	Execution       *release.ExecutionReport `json:"execution,omitempty"`
	ObservedVersion string                   `json:"observed_version"`
	RestoredVersion string                   `json:"restored_version"`

	ID              string           `json:"id"`
	InputDigest     string           `json:"input_digest"`
	AffectedSiteIDs []string         `json:"affected_site_ids"`
	Changes         []release.Change `json:"changes"`
	State           domain.State     `json:"state"`
	Effective       bool             `json:"effective"`
}
type Identity interface {
	GuardWithin(transaction.Scope, identity.Actor) error
	RequireWithin(transaction.Scope, identity.Actor, identity.Action, []string) error
}
type Ingress interface {
	ReadForReleaseWithin(transaction.Scope, []string, map[string]int64) (ingress.ReleaseInputs, error)
	AffectedSitesWithin(transaction.Scope, string) ([]string, error)
}
type Materials interface {
	ReadMaterialsWithin(transaction.Scope, []deploy.Material) error
}

// HistoricalMaterials validates current binding compatibility, enabled state,
// revocation and validity for logical configuration. It never restores old keys.
type HistoricalMaterials interface {
	ValidateHistoricalWithin(transaction.Scope, []deploy.MaterialRequirement) error
}
type HistoricalIngress interface {
	ReadHistoricalForReleaseWithin(transaction.Scope, []string, map[string]int64, ingress.RevisionExport) (ingress.ReleaseInputs, error)
}
type UnavailableMaterials struct{}

func (UnavailableMaterials) ValidateHistoricalWithin(_ transaction.Scope, refs []deploy.MaterialRequirement) error {
	if len(refs) > 0 {
		return domain.ErrUnavailable
	}
	return nil
}

func (UnavailableMaterials) ReadMaterialsWithin(_ transaction.Scope, refs []deploy.Material) error {
	if len(refs) > 0 {
		return domain.ErrUnavailable
	}
	return nil
}

type Jobs interface {
	EnqueueWithin(transaction.Scope, string, string, json.RawMessage) (string, error)
}
type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type IDs interface{ NewID() (string, error) }
type Coordinator struct {
	nodes     *nodes.Service
	tx        transaction.Runner
	identity  Identity
	ingress   Ingress
	materials Materials
	releases  *release.Service
	jobs      Jobs
	audit     Audit
	ids       IDs
}

func New(tx transaction.Runner, id Identity, in Ingress, m Materials, r *release.Service, j Jobs, a Audit, ids IDs) *Coordinator {
	if m == nil {
		m = UnavailableMaterials{}
	}
	return &Coordinator{tx: tx, identity: id, ingress: in, materials: m, releases: r, jobs: j, audit: a, ids: ids}
}
func actor(a ActorRef) identity.Actor {
	return identity.Actor{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: identity.CredentialKind(a.CredentialKind), CredentialID: a.CredentialID}
}
func normalizeError(e error) error {
	if errors.Is(e, ingressdomain.ErrConflict) {
		return domain.ErrConflict
	}
	if errors.Is(e, ingressdomain.ErrInvalid) {
		return domain.ErrInvalid
	}
	if errors.Is(e, ingressdomain.ErrNotFound) {
		return ErrDenied
	}
	if errors.Is(e, access.ErrDenied) || errors.Is(e, ingress.ErrDenied) || errors.Is(e, domain.ErrNotFound) {
		return ErrDenied
	}
	return e
}
func (c *Coordinator) within(ctx context.Context, a ActorRef, fn func(transaction.Scope) error) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return normalizeError(c.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := c.identity.GuardWithin(sc, actor(a)); e != nil {
			return e
		}
		return fn(sc)
	}))
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
func (c *Coordinator) require(sc transaction.Scope, a ActorRef, action identity.Action, ids []string) error {
	ids = unique(ids)
	if len(ids) == 0 {
		return ErrDenied
	}
	for i := 0; i < len(ids); i += 100 {
		end := i + 100
		if end > len(ids) {
			end = len(ids)
		}
		if e := c.identity.RequireWithin(sc, actor(a), action, ids[i:end]); e != nil {
			return e
		}
	}
	return nil
}
func (c *Coordinator) inputs(sc transaction.Scope, a ActorRef, sites []string, expected map[string]int64) (release.PrepareInput, error) {
	return c.inputsFromSource(sc, a, sites, expected, nil)
}
func (c *Coordinator) inputsFromSource(sc transaction.Scope, a ActorRef, sites []string, expected map[string]int64, source *release.Candidate) (release.PrepareInput, error) {
	var in ingress.ReleaseInputs
	var e error
	if source == nil {
		in, e = c.ingress.ReadForReleaseWithin(sc, sites, expected)
	} else {
		if source.State != domain.Succeeded {
			return release.PrepareInput{}, domain.ErrInvalid
		}
		owner, ok := c.ingress.(HistoricalIngress)
		if !ok {
			return release.PrepareInput{}, domain.ErrUnavailable
		}
		chosen := ingress.RevisionExport{}
		for _, old := range source.Snapshot.Sites {
			var v ingress.Site
			if e = mapValue(struct {
				ID    string            `json:"id"`
				Draft deploy.SiteConfig `json:"draft"`
			}{old.ID, old.Config}, &v); e != nil {
				return release.PrepareInput{}, e
			}
			chosen.Sites = append(chosen.Sites, v)
		}
		for _, old := range source.Snapshot.Targets {
			var v ingress.TargetGroup
			if e = mapValue(struct {
				ID     string              `json:"id"`
				Config deploy.TargetConfig `json:"config"`
			}{old.ID, old.Config}, &v); e != nil {
				return release.PrepareInput{}, e
			}
			chosen.Targets = append(chosen.Targets, v)
		}
		in, e = owner.ReadHistoricalForReleaseWithin(sc, sites, expected, chosen)
	}
	if e != nil {
		return release.PrepareInput{}, e
	}
	if e = c.require(sc, a, identity.Publish, in.AuthorizationSiteIDs); e != nil {
		return release.PrepareInput{}, e
	}
	mapped := release.Inputs{SelectedSiteIDs: in.SelectedSiteIDs, SelectedTargetIDs: in.SelectedTargetIDs, AuthorizationSiteIDs: in.AuthorizationSiteIDs, Expected: in.Expected}
	// Conversion through JSON gives this boundary an explicit independent DTO copy.
	for _, v := range in.Export.Sites {
		h := release.SiteHead{ID: v.ID, DraftRevision: v.Revision, PublishedRevision: v.PublishedRevision}
		if v.Draft != nil {
			h.Draft = &deploy.SiteConfig{}
			if e = mapValue(v.Draft, h.Draft); e != nil {
				return release.PrepareInput{}, e
			}
		}
		if v.Published != nil {
			h.Published = &deploy.SiteConfig{}
			if e = mapValue(v.Published, h.Published); e != nil {
				return release.PrepareInput{}, e
			}
		}
		if source != nil {
			for _, old := range source.Snapshot.Sites {
				if old.ID == h.ID {
					h.LogicalRevision = old.Revision
				}
			}
		}
		mapped.Sites = append(mapped.Sites, h)
	}
	for _, v := range in.Export.Targets {
		h := release.TargetHead{ID: v.ID, DraftRevision: v.Revision, PublishedRevision: v.PublishedRevision, Draft: &deploy.TargetConfig{}}
		if e = mapValue(v.Config, h.Draft); e != nil {
			return release.PrepareInput{}, e
		}
		if v.Published != nil {
			h.Published = &deploy.TargetConfig{}
			if e = mapValue(v.Published, h.Published); e != nil {
				return release.PrepareInput{}, e
			}
		}
		if source != nil {
			for _, old := range source.Snapshot.Targets {
				if old.ID == h.ID {
					h.LogicalRevision = old.Revision
				}
			}
		}
		mapped.Targets = append(mapped.Targets, h)
	}
	out, e := release.Build(mapped)
	if e != nil {
		return out, e
	}
	if source != nil {
		out.Snapshot.SourceReleaseID = source.ID
		provider, ok := c.materials.(HistoricalMaterials)
		if !ok {
			return release.PrepareInput{}, domain.ErrUnavailable
		}
		if e = provider.ValidateHistoricalWithin(sc, release.Requirements(out.Snapshot)); e != nil {
			return release.PrepareInput{}, domain.ErrUnavailable
		}
	}
	if e = c.materials.ReadMaterialsWithin(sc, release.Materials(out.Snapshot)); e != nil {
		return release.PrepareInput{}, domain.ErrUnavailable
	}
	return out, nil
}
func mapValue(from, to any) error {
	b, e := json.Marshal(from)
	if e != nil {
		return e
	}
	return json.Unmarshal(b, to)
}
func view(v release.Candidate) CandidateView {
	return CandidateView{ID: v.ID, InputDigest: v.InputDigest, AffectedSiteIDs: v.AffectedSiteIDs, Changes: v.Changes, State: v.State, Effective: v.Effective, ObservedVersion: v.ObservedVersion, RestoredVersion: v.RestoredVersion}
}
func (c *Coordinator) Prepare(ctx context.Context, a ActorRef, sites []string, expected map[string]int64) (out CandidateView, err error) {
	err = c.within(ctx, a, func(sc transaction.Scope) error {
		in, e := c.inputs(sc, a, sites, expected)
		if e != nil {
			return e
		}
		v, e := c.releases.PrepareWithin(sc, in)
		if e != nil {
			return e
		}
		out = view(v)
		return nil
	})
	if err != nil {
		return CandidateView{}, err
	}
	return
}

// PrepareHistorical creates a fresh candidate from a verified logical version;
// current heads guard concurrency, while current identity and refs govern ACL.
func (c *Coordinator) PrepareHistorical(ctx context.Context, a ActorRef, sourceID string, sites []string, expected map[string]int64) (out CandidateView, err error) {
	err = c.within(ctx, a, func(sc transaction.Scope) error {
		source, e := c.releases.ReadWithin(sc, sourceID)
		if e != nil {
			return e
		}
		in, e := c.inputsFromSource(sc, a, sites, expected, &source)
		if e != nil {
			return e
		}
		v, e := c.releases.PrepareWithin(sc, in)
		if e != nil {
			return e
		}
		out = view(v)
		return nil
	})
	if err != nil {
		return CandidateView{}, err
	}
	return
}
func (c *Coordinator) Publish(ctx context.Context, a ActorRef, id string) (result string, err error) {
	err = c.within(ctx, a, func(sc transaction.Scope) error {
		v, e := c.releases.ReadWithin(sc, id)
		if e != nil {
			return e
		}
		var source *release.Candidate
		if v.Snapshot.SourceReleaseID != "" {
			old, e := c.releases.ReadWithin(sc, v.Snapshot.SourceReleaseID)
			if e != nil {
				return e
			}
			source = &old
		}
		in, e := c.inputsFromSource(sc, a, v.SelectedSiteIDs, v.Expected, source)
		if e != nil {
			return e
		}
		digest, e := c.releases.Digest(in)
		if e != nil {
			return e
		}
		if digest != v.InputDigest {
			return domain.ErrConflict
		}
		var created bool
		result, created, e = c.releases.QueueWithin(sc, id)
		if e != nil {
			return e
		}
		if !created {
			return nil
		}
		payload, _ := json.Marshal(struct {
			ReleaseID string   `json:"release_id"`
			Publisher ActorRef `json:"publisher"`
		}{result, a})
		var targets []domain.NodeRef
		if c.nodes != nil {
			targets, e = c.nodes.TargetsWithin(sc)
			if e != nil {
				return e
			}
		}
		if len(targets) > 0 {
			targets, e = c.nodes.SetDesiredWithin(sc, result)
			if e != nil {
				return e
			}
			directed, ok := c.jobs.(interface {
				EnqueueTargetWithin(transaction.Scope, string, string, json.RawMessage, jobs.ClaimTarget) (string, error)
			})
			if !ok {
				return domain.ErrUnavailable
			}
			for _, node := range targets {
				if _, e = directed.EnqueueTargetWithin(sc, "deployment.node.apply.v1", result, payload, jobs.ClaimTarget{NodeID: node.ID, Epoch: node.Epoch}); e != nil {
					return e
				}
			}
		} else if _, e = c.jobs.EnqueueWithin(sc, "deployment.apply", result, payload); e != nil {
			return e
		}
		eid, e := c.ids.NewID()
		if e != nil {
			return e
		}
		return c.audit.Append(sc, audit.Event{ID: eid, ActorID: a.UserID, Action: "deployment.release.queued", Payload: payload})
	})
	if err != nil {
		return "", err
	}
	return
}

// authorizeHistory uses current references, not prepare-time ACL, and never exposes snapshot.
func (c *Coordinator) authorizeHistory(sc transaction.Scope, a ActorRef, v release.Candidate) error {
	ids := append([]string{}, v.AffectedSiteIDs...)
	resources := []string{}
	for key := range v.Expected {
		if len(key) > 7 && key[:7] == "target:" {
			resources = append(resources, key[7:])
		}
	}
	for _, s := range v.Snapshot.Sites {
		selected := false
		for _, id := range v.SelectedSiteIDs {
			if id == s.ID {
				selected = true
			}
		}
		if !selected {
			continue
		}
		if s.Config.DefaultTarget.ID != "" {
			resources = append(resources, s.Config.DefaultTarget.ID)
		}
		for _, r := range s.Config.Routes {
			resources = append(resources, r.Target.ID)
		}
		if s.Config.EntryCertificate != nil {
			resources = append(resources, s.Config.EntryCertificate.ID)
		}
		if s.Config.ClientVerification.Trust != nil {
			resources = append(resources, s.Config.ClientVerification.Trust.ID)
		}
	}
	targetResources := unique(resources)
	for _, target := range v.Snapshot.Targets {
		chosen := false
		for _, id := range targetResources {
			if id == target.ID {
				chosen = true
			}
		}
		if !chosen {
			continue
		}
		if target.Config.Trust != nil {
			resources = append(resources, target.Config.Trust.ID)
		}
		if target.Config.ClientCertificate != nil {
			resources = append(resources, target.Config.ClientCertificate.ID)
		}
	}
	for _, id := range unique(resources) {
		refs, e := c.ingress.AffectedSitesWithin(sc, id)
		if e != nil {
			return e
		}
		ids = append(ids, refs...)
	}
	return c.require(sc, a, identity.View, ids)
}
func (c *Coordinator) Version(ctx context.Context, a ActorRef, id string) (out CandidateView, err error) {
	err = c.within(ctx, a, func(sc transaction.Scope) error {
		v, e := c.releases.ReadWithin(sc, id)
		if e != nil {
			return e
		}
		if e = c.authorizeHistory(sc, a, v); e != nil {
			return e
		}
		out = view(v)
		if e = c.attachNodeProgress(sc, &out); e != nil {
			return e
		}
		report, e := c.releases.ExecutionWithin(sc, id)
		if e != nil {
			return e
		}
		// Whole-artifact evidence may include unrelated published sites. The
		// public view is limited to this candidate's currently authorized closure.
		if report.RouteVerification != nil {
			safe := *report.RouteVerification
			safe.Routes = nil
			allowed := map[string]bool{}
			for _, id := range v.AffectedSiteIDs {
				allowed[id] = true
			}
			safe.BusinessVerified = true
			for _, route := range report.RouteVerification.Routes {
				if allowed[route.SiteID] {
					safe.Routes = append(safe.Routes, route)
					if route.Outcome != "verified" {
						safe.BusinessVerified = false
					}
				}
			}
			if len(safe.Routes) == 0 {
				safe.BusinessVerified = false
			}
			report.RouteVerification = &safe
		}
		out.Execution = &report
		return nil
	})
	if err != nil {
		return CandidateView{}, err
	}
	return
}

type VersionsPage struct {
	Items      []CandidateView `json:"items"`
	Limit      int             `json:"limit"`
	Offset     int             `json:"offset"`
	HasMore    bool            `json:"has_more"`
	NextOffset *int            `json:"next_offset"`
}

func (c *Coordinator) Versions(ctx context.Context, a ActorRef, limit, offset int) (out VersionsPage, err error) {
	out = VersionsPage{Items: []CandidateView{}, Limit: limit, Offset: offset}
	err = c.within(ctx, a, func(sc transaction.Scope) error {
		items, more, e := c.releases.ListPageWithin(sc, limit, offset)
		out.HasMore = more
		if more {
			next := offset + limit
			out.NextOffset = &next
		}
		if e != nil {
			return e
		}
		for _, v := range items {
			if e = c.authorizeHistory(sc, a, v); e != nil {
				if errors.Is(e, access.ErrDenied) || errors.Is(e, ErrDenied) {
					continue
				}
				return e
			}
			item := view(v)
			if e = c.attachNodeProgress(sc, &item); e != nil {
				return e
			}
			out.Items = append(out.Items, item)
		}
		return nil
	})
	if err != nil {
		return VersionsPage{}, err
	}
	return
}

func (c *Coordinator) SetNodes(service *nodes.Service) { c.nodes = service }
func (c *Coordinator) attachNodeProgress(sc transaction.Scope, out *CandidateView) error {
	if c.nodes == nil {
		return nil
	}
	summary, err := c.nodes.SummaryWithin(sc, out.ID)
	if err != nil {
		return err
	}
	if summary.Expected > 0 {
		out.NodeProgress = &summary
		out.Effective = out.Effective && summary.Complete
	}
	return nil
}
