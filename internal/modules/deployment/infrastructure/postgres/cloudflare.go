package postgres

import (
	"context"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/deployment/application"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
)

func (r *Runtime) Cloudflare(ctx context.Context) (out edge.CloudflareSet, err error) {
	err = r.tx.Within(ctx, func(sc transaction.Scope) error {
		return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
			body, e := q.CloudflareRanges(ctx)
			if e != nil {
				return e
			}
			return json.Unmarshal(body, &out)
		})
	})
	if errors.Is(err, domain.ErrNotFound) {
		err = nil
	}
	return
}
func (r *Runtime) SaveCloudflare(ctx context.Context, v edge.CloudflareSet) error {
	return r.tx.Within(ctx, func(sc transaction.Scope) error {
		return use(sc, func(ctx context.Context, q *dbgen.Queries) error {
			if _, e := q.RuntimeFence(ctx); e != nil {
				return e
			}
			body, e := json.Marshal(v)
			if e != nil {
				return e
			}
			old, e := q.CloudflareRanges(ctx)
			var previous edge.CloudflareSet
			if e == nil && json.Unmarshal(old, &previous) == nil && previous.Generation == v.Generation {
				return nil
			}
			if e = q.SaveCloudflareRanges(ctx, dbgen.SaveCloudflareRangesParams{Generation: v.Generation, Body: body}); e != nil {
				return e
			}
			_, e = q.RuntimeDirty(ctx)
			return e
		})
	})
}
func (r *Runtime) BindCloudflareWithin(sc transaction.Scope, s app.Snapshot, state edge.RuntimeState) (edge.RuntimeState, error) {
	needed := false
	for _, site := range s.Sites {
		if site.Config.Enabled && site.Config.Cloudflare.Mode == "proxied" {
			needed = true
		}
	}
	if !needed {
		return state, nil
	}
	e := use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		if _, e := q.RuntimeReadFence(ctx); e != nil {
			return e
		}
		body, e := q.CloudflareRanges(ctx)
		if e != nil {
			return e
		}
		return json.Unmarshal(body, &state.Cloudflare)
	})
	if errors.Is(e, domain.ErrNotFound) {
		state.Cloudflare = edge.CloudflareSet{Generation: "unavailable"}
		e = nil
	}
	state.Generation = digest([]string{state.Generation, state.Cloudflare.Generation})
	return state, e
}
