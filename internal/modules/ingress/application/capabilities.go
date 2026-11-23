package application

import (
	"context"
	"errors"
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/platform/transaction"
)

// ErrNotFound is the public catalog absence contract; adapters preserve other errors.
var ErrNotFound = domain.ErrNotFound

// CreationCapabilities are advisory hints for current credentials. Mutations
// always perform their existing authoritative checks again. Group IDs are only
// echoed when the caller may create inside that requested group; no graph details
// or names cross this read boundary.
type CreationCapabilities struct {
	CreateSiteGroupIDs  []string `json:"create_site_group_ids"`
	CreateUngroupedSite bool     `json:"create_ungrouped_site"`
	CreateTarget        bool     `json:"create_target"`
	ManageGroups        bool     `json:"manage_groups"`
}

func (s *Service) Capabilities(ctx context.Context, a ActorRef, groupIDs []string) (CreationCapabilities, error) {
	out := CreationCapabilities{CreateSiteGroupIDs: []string{}}
	if len(groupIDs) > 100 {
		return out, domain.ErrInvalid
	}
	ids, e := domain.IDs(groupIDs)
	if e != nil {
		return out, e
	}
	e = s.within(ctx, a, false, func(sc transaction.Scope) error {
		err := s.require(sc, a, "manage", nil)
		if err == nil {
			out.CreateUngroupedSite = true
			out.CreateTarget = true
			out.ManageGroups = true
		} else if !errors.Is(err, ErrDenied) {
			return err
		}
		if len(ids) == 0 {
			return nil
		}
		graph, e := s.repo.Graph(sc)
		if e != nil {
			return e
		}
		known := map[string]bool{}
		for _, g := range graph.Groups {
			known[g.ID] = true
		}
		for _, id := range ids {
			if !known[id] {
				continue
			}
			if e = s.auth.RequireGroupCreateWithin(sc, a, []string{id}); e == nil {
				out.CreateSiteGroupIDs = append(out.CreateSiteGroupIDs, id)
			} else if !errors.Is(e, ErrDenied) {
				return e
			}
		}
		return nil
	})
	if e != nil {
		return CreationCapabilities{}, e
	}
	return out, nil
}
