package release

import (
	"bytes"
	"encoding/json"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/domain"
	"sort"
)

// Inputs is consumer-owned: immutable revision heads mapped by integration.
type SiteHead struct {
	LogicalRevision                  int64
	ID                               string
	DraftRevision, PublishedRevision int64
	Draft, Published                 *app.SiteConfig
}
type TargetHead struct {
	LogicalRevision                  int64
	ID                               string
	DraftRevision, PublishedRevision int64
	Draft, Published                 *app.TargetConfig
}
type Inputs struct {
	Sites                                                    []SiteHead
	Targets                                                  []TargetHead
	SelectedSiteIDs, SelectedTargetIDs, AuthorizationSiteIDs []string
	Expected                                                 map[string]int64
}

func contains(v []string, id string) bool {
	for _, s := range v {
		if s == id {
			return true
		}
	}
	return false
}
func refs(c app.SiteConfig) []string {
	out := []string{}
	if c.DefaultTarget.ID != "" {
		out = append(out, c.DefaultTarget.ID)
	}
	for _, r := range c.Routes {
		out = append(out, r.Target.ID)
	}
	return out
}

// Build chooses explicit draft heads and otherwise preserves published versions.
func Build(in Inputs) (PrepareInput, error) {
	out := PrepareInput{Snapshot: app.Snapshot{Version: "deployment/v1", Sites: []app.Site{}, Targets: []app.Target{}}, SelectedSiteIDs: in.SelectedSiteIDs, Expected: in.Expected, Changes: []Change{}}
	// Freeze the complete exported published base BEFORE selected versions
	// replace content. Unpublished, unselected draft-only resources are absent.
	out.PublishedBase = map[string]int64{}
	for _, h := range in.Sites {
		out.PublishedBase["site:"+h.ID] = h.PublishedRevision
	}
	for _, h := range in.Targets {
		out.PublishedBase["target:"+h.ID] = h.PublishedRevision
	}
	needed := map[string]bool{}
	affected := map[string]bool{}
	for _, h := range in.Sites {
		cfg, revision := h.Published, h.PublishedRevision
		if contains(in.SelectedSiteIDs, h.ID) {
			if h.Draft == nil || in.Expected["site:"+h.ID] != h.DraftRevision {
				return out, domain.ErrConflict
			}
			cfg, revision = h.Draft, h.DraftRevision
			if h.LogicalRevision > 0 {
				revision = h.LogicalRevision
			}
			affected[h.ID] = true
			out.Changes = append(out.Changes, Change{Kind: "site", ID: h.ID, Before: h.PublishedRevision, After: revision, Fields: changedFields(h.Published, cfg)})
		}
		if cfg == nil {
			continue
		}
		out.Snapshot.Sites = append(out.Snapshot.Sites, app.Site{ID: h.ID, Revision: revision, Config: *cfg})
		for _, id := range refs(*cfg) {
			needed[id] = true
			if contains(in.SelectedTargetIDs, id) {
				affected[h.ID] = true
			}
		}
	}
	for _, id := range in.SelectedTargetIDs {
		needed[id] = true
	}
	for _, h := range in.Targets {
		if !needed[h.ID] {
			continue
		}
		cfg, revision := h.Published, h.PublishedRevision
		if contains(in.SelectedTargetIDs, h.ID) {
			if h.Draft == nil || in.Expected["target:"+h.ID] != h.DraftRevision {
				return out, domain.ErrConflict
			}
			cfg, revision = h.Draft, h.DraftRevision
			if h.LogicalRevision > 0 {
				revision = h.LogicalRevision
			}
			out.Changes = append(out.Changes, Change{Kind: "target", ID: h.ID, Before: h.PublishedRevision, After: revision, Fields: changedFields(h.Published, cfg)})
		}
		if cfg == nil || revision < 1 {
			return out, domain.ErrInvalid
		}
		out.Snapshot.Targets = append(out.Snapshot.Targets, app.Target{ID: h.ID, Revision: revision, Config: *cfg})
		delete(needed, h.ID)
	}
	if len(needed) > 0 || len(affected) == 0 {
		return out, domain.ErrInvalid
	}
	for id := range affected {
		out.AffectedSiteIDs = append(out.AffectedSiteIDs, id)
	}
	sort.Strings(out.AffectedSiteIDs)
	sort.Slice(out.Snapshot.Sites, func(i, j int) bool { return out.Snapshot.Sites[i].ID < out.Snapshot.Sites[j].ID })
	sort.Slice(out.Snapshot.Targets, func(i, j int) bool { return out.Snapshot.Targets[i].ID < out.Snapshot.Targets[j].ID })
	sort.Slice(out.Changes, func(i, j int) bool {
		return out.Changes[i].Kind+out.Changes[i].ID < out.Changes[j].Kind+out.Changes[j].ID
	})
	return out, nil
}

// Materials is calculated only from chosen versions, never unused drafts.
func Materials(s app.Snapshot) []app.Material {
	out := []app.Material{}
	seen := map[app.Material]bool{}
	add := func(kind string, r *app.MaterialRef) {
		if r == nil {
			return
		}
		m := app.Material{Kind: kind, ID: r.ID, Revision: r.Revision}
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	for _, v := range s.Sites {
		add("certificate", v.Config.EntryCertificate)
		add("trust", v.Config.ClientVerification.Trust)
		if v.Config.Cloudflare.RequireOriginPull {
			add("origin_pull_trust", v.Config.ClientVerification.Trust)
		}
	}
	for _, v := range s.Targets {
		add("trust", v.Config.Trust)
		add("certificate", v.Config.ClientCertificate)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Revision < out[j].Revision
	})
	return out
}

// Requirements carries expected names and usage to the certificates owner.
// No key, DER, signer or raw issuance protocol crosses this boundary.
func Requirements(s app.Snapshot) []app.MaterialRequirement {
	out := []app.MaterialRequirement{}
	add := func(kind string, r *app.MaterialRef, names []string, usage string) {
		if r != nil {
			out = append(out, app.MaterialRequirement{Ref: app.Material{Kind: kind, ID: r.ID, Revision: r.Revision}, Names: append([]string{}, names...), Usage: usage})
		}
	}
	for _, v := range s.Sites {
		add("certificate", v.Config.EntryCertificate, v.Config.Domains, "serverAuth")
		add("trust", v.Config.ClientVerification.Trust, nil, "clientAuth")
		if v.Config.Cloudflare.RequireOriginPull {
			add("origin_pull_trust", v.Config.ClientVerification.Trust, nil, "clientAuth")
		}
	}
	for _, v := range s.Targets {
		names := []string{}
		if v.Config.TLSNameMode == "fixed" {
			names = append(names, v.Config.TLSName)
		} else {
			for _, m := range v.Config.Members {
				names = append(names, m.TLSName)
			}
		}
		add("trust", v.Config.Trust, names, "serverAuth")
		add("certificate", v.Config.ClientCertificate, nil, "clientAuth")
	}
	return out
}

func changedFields(before, after any) []string {
	oldBody, _ := json.Marshal(before)
	newBody, _ := json.Marshal(after)
	oldFields := map[string]json.RawMessage{}
	newFields := map[string]json.RawMessage{}
	_ = json.Unmarshal(oldBody, &oldFields)
	_ = json.Unmarshal(newBody, &newFields)
	out := []string{}
	for name, value := range newFields {
		if !bytes.Equal(oldFields[name], value) {
			out = append(out, name)
		}
	}
	for name := range oldFields {
		if _, exists := newFields[name]; !exists {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
