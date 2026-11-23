package release_test

import (
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/domain"
	"testing"
)

func TestBuildRequiresExplicitDependencyAndRetainsUnselectedHeads(t *testing.T) {
	published := app.SiteConfig{Enabled: true, Domains: []string{"old.test"}, DefaultTarget: app.TargetRef{ID: "target"}}
	draft := published
	draft.Enabled = false
	targetPublished := app.TargetConfig{Name: "old", Protocol: "http"}
	targetDraft := targetPublished
	targetDraft.Protocol = "https"
	targetDraft.Trust = &app.MaterialRef{ID: "unused-secret", Revision: 2}
	in := release.Inputs{Sites: []release.SiteHead{{ID: "a", DraftRevision: 2, Draft: &draft, PublishedRevision: 1, Published: &published}, {ID: "b", DraftRevision: 2, Draft: &draft, PublishedRevision: 1, Published: &published}, {ID: "new", DraftRevision: 1, Draft: &draft}}, Targets: []release.TargetHead{{ID: "target", DraftRevision: 2, Draft: &targetDraft, PublishedRevision: 1, Published: &targetPublished}}, SelectedSiteIDs: []string{"a"}, Expected: map[string]int64{"site:a": 2}}
	out, e := release.Build(in)
	if e != nil {
		t.Fatal(e)
	}
	if len(out.Snapshot.Sites) != 2 || out.Snapshot.Sites[0].Revision != 2 || out.Snapshot.Sites[0].Config.Enabled || out.Snapshot.Sites[1].Revision != 1 || !out.Snapshot.Sites[1].Config.Enabled || out.Snapshot.Targets[0].Revision != 1 || len(release.Materials(out.Snapshot)) != 0 {
		t.Fatal("version selection violated", out)
	}
	in.Targets[0].Published = nil
	if _, e = release.Build(in); !errors.Is(e, domain.ErrInvalid) {
		t.Fatal("missing published target selected implicitly", e)
	}
	in.SelectedTargetIDs = []string{"target"}
	in.Expected["target:target"] = 2
	out, e = release.Build(in)
	if e != nil || len(out.AffectedSiteIDs) != 2 || len(release.Materials(out.Snapshot)) != 1 {
		t.Fatal("explicit shared closure incorrect", out, e)
	}
}

func TestOriginPullUsesExplicitTrustIdentity(t *testing.T) {
	s := app.Snapshot{Sites: []app.Site{{Config: app.SiteConfig{Cloudflare: app.CFPolicy{Mode: "proxied", RequireOriginPull: true}, ClientVerification: app.ClientVerification{Mode: "required", Trust: &app.MaterialRef{ID: "11111111-1111-4111-8111-111111111111", Revision: 2}}}}}}
	for _, r := range release.Materials(s) {
		if r.ID != "11111111-1111-4111-8111-111111111111" {
			t.Fatal("implicit unavailable trust identity", r)
		}
	}
}
