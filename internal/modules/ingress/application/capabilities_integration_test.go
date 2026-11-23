//go:build integration

package application_test

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	"testing"
)

func TestCreationCapabilitiesDistinguishSiteVisibilityFromGroupGrant(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	group, e := f.s.SaveGroup(ctx, f.admin, domain.SiteGroup{Name: "create-scope"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	hidden, e := f.s.SaveGroup(ctx, f.admin, domain.SiteGroup{Name: "hidden"}, 0)
	if e != nil {
		t.Fatal(e)
	}
	site := f.site(t, "sitegrant", []string{group.ID})
	f.grant(t, f.editor, "site", site.ID)
	caps, e := f.s.Capabilities(ctx, f.editor, []string{group.ID, hidden.ID})
	if e != nil {
		t.Fatal(e)
	}
	if caps.CreateUngroupedSite || caps.CreateTarget || caps.ManageGroups || len(caps.CreateSiteGroupIDs) != 0 {
		t.Fatalf("site view widened creation: %+v", caps)
	}
	f.grant(t, f.editor, "group", group.ID)
	caps, e = f.s.Capabilities(ctx, f.editor, []string{group.ID, hidden.ID})
	if e != nil {
		t.Fatal(e)
	}
	if len(caps.CreateSiteGroupIDs) != 1 || caps.CreateSiteGroupIDs[0] != group.ID {
		t.Fatalf("group create scope lost or hidden group %s leaked: %+v", hidden.ID, caps)
	}
	caps, e = f.s.Capabilities(ctx, f.admin, []string{group.ID, hidden.ID})
	if e != nil || !caps.CreateUngroupedSite || !caps.CreateTarget || !caps.ManageGroups || len(caps.CreateSiteGroupIDs) != 2 {
		t.Fatalf("admin capabilities: %+v %v", caps, e)
	}
	// A narrowed token never inherits the account's interactive creation scope.
	tokenID, _ := f.ids.NewID()
	raw, _ := f.ids.Random()
	if _, e = f.p.Exec(ctx, `INSERT INTO identity_tokens(id,account_id,digest,auth_version,actions,site_ids,expires) VALUES($1,$2,$3,1,ARRAY['view','edit'],ARRAY[$4],now()+interval '1 hour')`, tokenID, f.admin.UserID, f.ids.Digest(raw), site.ID); e != nil {
		t.Fatal(e)
	}
	token := app.ActorRef{UserID: f.admin.UserID, AuthVersion: 1, CredentialKind: "token", CredentialID: tokenID}
	caps, e = f.s.Capabilities(ctx, token, []string{group.ID})
	if e != nil || caps.CreateTarget || caps.CreateUngroupedSite || caps.ManageGroups || len(caps.CreateSiteGroupIDs) != 0 {
		t.Fatalf("token widened creation: %+v %v", caps, e)
	}
	if _, e = f.p.Exec(ctx, "UPDATE identity_tokens SET revoked=true WHERE id=$1", tokenID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Capabilities(ctx, token, nil); e == nil {
		t.Fatal("revoked token got capabilities")
	}
	if _, e = f.p.Exec(ctx, "UPDATE identity_accounts SET role='readonly' WHERE id=$1", f.editor.UserID); e != nil {
		t.Fatal(e)
	}
	caps, e = f.s.Capabilities(ctx, f.editor, []string{group.ID})
	if e != nil || len(caps.CreateSiteGroupIDs) != 0 || caps.CreateTarget {
		t.Fatalf("current downgrade ignored: %+v %v", caps, e)
	}
	if _, e = f.p.Exec(ctx, "UPDATE identity_accounts SET state='disabled' WHERE id=$1", f.editor.UserID); e != nil {
		t.Fatal(e)
	}
	if _, e = f.s.Capabilities(ctx, f.editor, []string{group.ID, hidden.ID}); e == nil {
		t.Fatal("disabled credential got capability metadata")
	}
	f.p.Close()
	if _, e = f.s.Capabilities(ctx, f.admin, nil); e == nil || errors.Is(e, app.ErrDenied) {
		t.Fatalf("storage failure became permissions: %v", e)
	}

}
