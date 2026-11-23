// Package postgres privately maps ingress aggregates to sqlc and PostgreSQL.
package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	"gatebeam/internal/modules/ingress/infrastructure/postgres/dbgen"
	platformpg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"net/netip"
	"strings"
)

type Store struct{}

func New() *Store { return &Store{} }
func use(sc transaction.Scope, fn func(context.Context, *dbgen.Queries) error) error {
	return platformpg.Use(sc, func(ctx context.Context, tx pgx.Tx) error {
		e := fn(ctx, dbgen.New(tx))
		var pe *pgconn.PgError
		if errors.As(e, &pe) {
			switch pe.Code {
			case "23505":
				return domain.ErrConflict
			case "23503":
				return domain.ErrReferenced
			case "23514", "22P02":
				return domain.ErrInvalid
			}
		}
		return e
	})
}
func id(v string) pgtype.UUID { var u pgtype.UUID; _ = u.Scan(v); return u }
func changed(n int64, e error) error {
	if e != nil {
		return e
	}
	if n != 1 {
		return domain.ErrConflict
	}
	return nil
}
func (*Store) ReadLock(sc transaction.Scope) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error { return q.ReadLock(ctx) })
}
func (*Store) WriteLock(sc transaction.Scope) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error { return q.WriteLock(ctx) })
}
func (*Store) SiteGroups(sc transaction.Scope, siteID string) ([]string, error) {
	var groups []string
	e := use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		var e error
		groups, e = q.SiteGroups(ctx, id(siteID))
		if errors.Is(e, pgx.ErrNoRows) {
			return domain.ErrNotFound
		}
		return e
	})
	return groups, e
}
func (*Store) Graph(sc transaction.Scope) (application.Graph, error) {
	out := application.Graph{Sites: []domain.Site{}, Targets: []domain.TargetGroup{}, Groups: []domain.SiteGroup{}}
	e := use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		rows, e := q.Sites(ctx)
		if e != nil {
			return e
		}
		for _, r := range rows {
			v := domain.Site{ID: r.SID, Deleted: r.Deleted, Name: r.Name, GroupIDs: r.Groups, Revision: r.DraftRevision, PublishedRevision: r.PublishedRevision}
			if e = json.Unmarshal(r.Config, &v.Draft); e != nil {
				return e
			}
			if len(r.Published) > 0 {
				v.Published = &domain.SiteConfig{}
				if e = json.Unmarshal(r.Published, v.Published); e != nil {
					return e
				}
			}
			out.Sites = append(out.Sites, v)
		}
		targets, e := q.Targets(ctx)
		if e != nil {
			return e
		}
		for _, r := range targets {
			v := domain.TargetGroup{ID: r.TID, Revision: r.DraftRevision, PublishedRevision: r.PublishedRevision}
			if e = json.Unmarshal(r.Config, &v.Config); e != nil {
				return e
			}
			if len(r.Published) > 0 {
				v.Published = &domain.TargetConfig{}
				if e = json.Unmarshal(r.Published, v.Published); e != nil {
					return e
				}
			}
			out.Targets = append(out.Targets, v)
		}
		groups, e := q.Groups(ctx)
		if e != nil {
			return e
		}
		for _, r := range groups {
			out.Groups = append(out.Groups, domain.SiteGroup{ID: r.ID, Name: r.Name, Revision: r.Revision})
		}
		return nil
	})
	return out, e
}
func (*Store) SaveSite(sc transaction.Scope, v domain.Site, expected int64) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		b, e := json.Marshal(v.Draft)
		if e != nil {
			return e
		}
		if expected == 0 {
			if e = q.CreateSite(ctx, dbgen.CreateSiteParams{ID: id(v.ID), Name: v.Name}); e != nil {
				return e
			}
		} else {
			if e = changed(q.UpdateSite(ctx, dbgen.UpdateSiteParams{ID: id(v.ID), Revision: v.Revision, Expected: expected})); e != nil {
				return e
			}
		}
		if e = q.AppendSiteRevision(ctx, dbgen.AppendSiteRevisionParams{ID: id(v.ID), Revision: v.Revision, Config: b}); e != nil {
			return e
		}
		if e = q.ClearGroups(ctx, id(v.ID)); e != nil {
			return e
		}
		for _, g := range v.GroupIDs {
			if e = q.AddGroup(ctx, dbgen.AddGroupParams{SiteID: id(v.ID), GroupID: id(g)}); e != nil {
				return e
			}
		}
		if e = q.ClearDomains(ctx, id(v.ID)); e != nil {
			return e
		}
		domains := map[string]bool{}
		for _, d := range v.Draft.Domains {
			domains[d] = true
		}
		if v.Published != nil {
			for _, d := range v.Published.Domains {
				domains[d] = true
			}
		}
		for d := range domains {
			if e = q.ClaimDomain(ctx, dbgen.ClaimDomainParams{ID: id(v.ID), Domain: d}); e != nil {
				return e
			}
		}
		return nil
	})
}
func (*Store) DeleteSite(sc transaction.Scope, v string, expected int64) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		if e := changed(q.DeleteSite(ctx, dbgen.DeleteSiteParams{ID: id(v), Expected: expected})); e != nil {
			return e
		}
		return q.ClearDomains(ctx, id(v))
	})
}
func (*Store) SaveTarget(sc transaction.Scope, v domain.TargetGroup, expected int64) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		b, e := json.Marshal(v.Config)
		if e != nil {
			return e
		}
		if expected == 0 {
			if e = q.CreateTarget(ctx, id(v.ID)); e != nil {
				return e
			}
		} else if e = changed(q.UpdateTarget(ctx, dbgen.UpdateTargetParams{ID: id(v.ID), Revision: v.Revision, Expected: expected})); e != nil {
			return e
		}
		return q.AppendTargetRevision(ctx, dbgen.AppendTargetRevisionParams{ID: id(v.ID), Revision: v.Revision, Config: b})
	})
}
func (*Store) DeleteTarget(sc transaction.Scope, v string, expected int64) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		return changed(q.DeleteTarget(ctx, dbgen.DeleteTargetParams{ID: id(v), Expected: expected}))
	})
}
func (*Store) SaveGroup(sc transaction.Scope, v domain.SiteGroup, expected int64) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		if expected == 0 {
			return changed(q.SaveGroup(ctx, dbgen.SaveGroupParams{ID: id(v.ID), Name: v.Name, Expected: 0}))
		}
		return changed(q.UpdateGroup(ctx, dbgen.UpdateGroupParams{ID: id(v.ID), Name: v.Name, Expected: expected}))
	})
}
func (*Store) DeleteGroup(sc transaction.Scope, v string, expected int64) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		return changed(q.DeleteGroup(ctx, dbgen.DeleteGroupParams{ID: id(v), Expected: expected}))
	})
}
func (*Store) ValidateSite(c domain.SiteConfig) error {
	for _, list := range [][]string{c.Access.Allow, c.Access.Deny, c.Cloudflare.TrustedProxyNetworks} {
		if len(list) > 1000 {
			return domain.ErrInvalid
		}
		for _, v := range list {
			if _, e := netip.ParsePrefix(v); e != nil {
				if _, e = netip.ParseAddr(v); e != nil {
					return domain.ErrInvalid
				}
			}
		}
	}
	return nil
}

var private = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}

func (*Store) ValidateTarget(c domain.TargetConfig) error {
	networks := []netip.Prefix{}
	for _, v := range c.AllowedNetworks {
		p, e := netip.ParsePrefix(v)
		if e != nil || p != p.Masked() {
			return domain.ErrInvalid
		}
		ok := false
		for _, allowed := range private {
			if allowed.Contains(p.Addr()) && p.Bits() >= allowed.Bits() {
				ok = true
			}
		}
		if !ok {
			return domain.ErrInvalid
		}
		networks = append(networks, p)
	}
	for _, m := range c.Members {
		if a, e := netip.ParseAddr(m.Address); e == nil {
			ok := false
			for _, p := range networks {
				if p.Contains(a) {
					ok = true
				}
			}
			if !ok || a.IsLoopback() || a.IsLinkLocalUnicast() || a.IsMulticast() || a.IsUnspecified() {
				return domain.ErrInvalid
			}
		} else if m.Address == "localhost" || strings.HasSuffix(m.Address, ".localhost") || m.Address == "metadata.google.internal" || !strings.Contains(m.Address, ".") {
			return domain.ErrInvalid
		}
	}
	return nil
}

func (*Store) CommandDigest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func (*Store) Receipt(sc transaction.Scope, k application.ReceiptKey) (application.Receipt, bool, error) {
	var out application.Receipt
	found := false
	e := use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		r, e := q.Receipt(ctx, dbgen.ReceiptParams{ActorID: k.ActorID, CredentialID: k.CredentialID, CredentialKind: k.CredentialKind, Method: k.Method, ResourcePath: k.Path, IdempotencyKey: k.Key})
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		out.Digest = r.CommandDigest
		if e = json.Unmarshal(r.Result, &out.Result); e != nil {
			return e
		}
		found = true
		return nil
	})
	return out, found, e
}
func (*Store) SaveReceipt(sc transaction.Scope, k application.ReceiptKey, v application.Receipt) error {
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		b, e := json.Marshal(v.Result)
		if e != nil {
			return e
		}
		return changed(q.SaveReceipt(ctx, dbgen.SaveReceiptParams{ActorID: k.ActorID, CredentialID: k.CredentialID, CredentialKind: k.CredentialKind, Method: k.Method, ResourcePath: k.Path, IdempotencyKey: k.Key, CommandDigest: v.Digest, Result: b}))
	})
}
