package application

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/transaction"
	"regexp"
)

type mutationScopeKey struct{}
type Mutation struct {
	Kind       string
	ResourceID string
	Expected   int64
	Site       *CreateSite
	Draft      *Draft
	Target     *domain.TargetConfig
	GroupName  string
	GroupIDs   []string
}

var keyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func (m *Mutation) normalize() error {
	if m.Expected < 0 {
		return domain.ErrInvalid
	}
	if m.ResourceID != "" && !domain.ValidID(m.ResourceID) {
		return domain.ErrInvalid
	}
	switch m.Kind {
	case "site.create":
		if m.Site == nil || m.ResourceID != "" || m.Expected != 0 {
			return domain.ErrInvalid
		}
		var e error
		m.Site.Name, e = domain.Name(m.Site.Name)
		if e != nil {
			return e
		}
		m.Site.GroupIDs, e = domain.IDs(m.Site.GroupIDs)
		if e != nil {
			return e
		}
		return m.Site.Config.Normalize()
	case "site.save":
		if m.Draft == nil || m.ResourceID == "" || m.Expected < 1 {
			return domain.ErrInvalid
		}
		m.Draft.SiteID = m.ResourceID
		return m.Draft.Config.Normalize()
	case "site.groups":
		if m.ResourceID == "" || m.Expected < 1 {
			return domain.ErrInvalid
		}
		var e error
		m.GroupIDs, e = domain.IDs(m.GroupIDs)
		return e
	case "target.save":
		if m.Target == nil || (m.ResourceID == "") != (m.Expected == 0) {
			return domain.ErrInvalid
		}
		return m.Target.Normalize()
	case "group.save":
		if (m.ResourceID == "") != (m.Expected == 0) {
			return domain.ErrInvalid
		}
		var e error
		m.GroupName, e = domain.Name(m.GroupName)
		return e
	case "site.delete", "target.delete", "group.delete":
		if m.ResourceID == "" || m.Expected < 1 {
			return domain.ErrInvalid
		}
		return nil
	}
	return domain.ErrInvalid
}
func (m Mutation) endpoint() (string, string) {
	switch m.Kind {
	case "site.create":
		return "POST", "/sites"
	case "site.save":
		return "PUT", "/sites/" + m.ResourceID + "/draft"
	case "site.groups":
		return "PUT", "/sites/" + m.ResourceID + "/groups"
	case "site.delete":
		return "DELETE", "/sites/" + m.ResourceID
	case "target.save":
		if m.ResourceID == "" {
			return "POST", "/targets"
		}
		return "PUT", "/targets/" + m.ResourceID
	case "target.delete":
		return "DELETE", "/targets/" + m.ResourceID
	case "group.save":
		if m.ResourceID == "" {
			return "POST", "/groups"
		}
		return "PUT", "/groups/" + m.ResourceID
	default:
		return "DELETE", "/groups/" + m.ResourceID
	}
}

// Mutate is the REST command entry point. Without a key the same guarded use
// cases run normally. With a key, authorization, mutation, audit and receipt all
// share one Scope and identity->graph write lock order. A replay rechecks current
// account/credential, roles, group existence and the entire current reference set.
func (s *Service) Mutate(ctx context.Context, a ActorRef, input Mutation, key string) (Revision, error) {
	var out Revision
	if key != "" && !keyPattern.MatchString(key) {
		return out, domain.ErrInvalid
	}
	// Clone before normalization, avoiding shared slice/pointer mutations for callers.
	b, e := json.Marshal(input)
	if e != nil {
		return out, domain.ErrInvalid
	}
	var m Mutation
	if json.Unmarshal(b, &m) != nil {
		return out, domain.ErrInvalid
	}
	if e = m.normalize(); e != nil {
		return out, e
	}
	if key == "" {
		return s.dispatch(ctx, a, m)
	}
	b, e = json.Marshal(m)
	if e != nil {
		return out, e
	}
	digest := s.repo.CommandDigest(b)
	method, path := m.endpoint()
	rk := ReceiptKey{ActorID: a.UserID, CredentialID: a.CredentialID, CredentialKind: a.CredentialKind, Method: method, Path: path, Key: key}
	e = s.within(ctx, a, true, func(sc transaction.Scope) error {
		g, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		receipt, found, e := s.repo.Receipt(sc, rk)
		if e != nil {
			return e
		}
		if found {
			// Creation scope can change after success. Authorize the registered
			// result against its CURRENT membership, including tombstones;
			// original command groups are not authority over the result.
			if m.Kind == "site.create" {
				e = s.require(sc, a, "edit", []string{receipt.Result.ResourceID})
			} else {
				e = s.authorizeMutation(sc, a, m, g)
			}
			if e != nil {
				return e
			}
			if receipt.Digest != digest {
				return domain.ErrConflict
			}
			out = receipt.Result
			return nil
		}
		if e = s.authorizeMutation(sc, a, m, g); e != nil {
			return e
		}
		out, e = s.dispatch(context.WithValue(sc.Context(), mutationScopeKey{}, sc), a, m)
		if e != nil {
			return e
		}
		return s.repo.SaveReceipt(sc, rk, Receipt{Digest: digest, Result: out})
	})
	if e != nil {
		return Revision{}, e
	}
	return out, nil
}
func (s *Service) authorizeMutation(sc transaction.Scope, a ActorRef, m Mutation, g Graph) error {
	switch m.Kind {
	case "site.create":
		if e := validGroups(g, m.Site.GroupIDs); e != nil {
			return e
		}
		if len(m.Site.GroupIDs) > 0 {
			return s.auth.RequireGroupCreateWithin(sc, a, m.Site.GroupIDs)
		}
		return s.require(sc, a, "manage", nil)
	case "site.save":
		return s.require(sc, a, "edit", []string{m.ResourceID})
	case "site.delete":
		return s.require(sc, a, "edit", []string{m.ResourceID})
	case "target.save", "target.delete":
		return s.require(sc, a, "edit", affected(g, m.ResourceID))
	default:
		return s.require(sc, a, "manage", nil)
	}
}
func (s *Service) dispatch(ctx context.Context, a ActorRef, m Mutation) (Revision, error) {
	switch m.Kind {
	case "site.create":
		v, e := s.CreateSite(ctx, a, *m.Site)
		return Revision{v.ID, v.Revision}, e
	case "site.save":
		return s.SaveDraft(ctx, a, *m.Draft, m.Expected)
	case "site.groups":
		e := s.SetGroups(ctx, a, m.ResourceID, m.GroupIDs, m.Expected)
		return Revision{m.ResourceID, m.Expected + 1}, e
	case "site.delete":
		e := s.DeleteSite(ctx, a, m.ResourceID, m.Expected)
		return Revision{m.ResourceID, m.Expected}, e
	case "target.save":
		v, e := s.SaveTarget(ctx, a, domain.TargetGroup{ID: m.ResourceID, Config: *m.Target}, m.Expected)
		return Revision{v.ID, v.Revision}, e
	case "target.delete":
		e := s.DeleteTarget(ctx, a, m.ResourceID, m.Expected)
		return Revision{m.ResourceID, m.Expected}, e
	case "group.save":
		v, e := s.SaveGroup(ctx, a, domain.SiteGroup{ID: m.ResourceID, Name: m.GroupName}, m.Expected)
		return Revision{v.ID, v.Revision}, e
	case "group.delete":
		e := s.DeleteGroup(ctx, a, m.ResourceID, m.Expected)
		return Revision{m.ResourceID, m.Expected}, e
	}
	return Revision{}, domain.ErrInvalid
}
