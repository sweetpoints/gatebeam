package postgres

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/deployment/application/release"
	"gatebeam/internal/modules/deployment/infrastructure/postgres/dbgen"
	"gatebeam/internal/platform/transaction"
	"strings"
)

func (*Store) SaveMaterialBindings(sc transaction.Scope, in []release.MaterialBinding) error {
	if in == nil {
		in = []release.MaterialBinding{}
	}
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	return use(sc, func(ctx context.Context, q *dbgen.Queries) error { return q.SaveMaterialBindings(ctx, b) })
}
func (*Store) CurrentMaterialBindings(sc transaction.Scope) (out release.VerifiedBindings, err error) {
	err = use(sc, func(ctx context.Context, q *dbgen.Queries) error {
		r, e := q.CurrentMaterialBindings(ctx)
		if e != nil {
			return e
		}
		_, generation, _ := strings.Cut(r.Version, "/")
		out = release.VerifiedBindings{ArtifactID: r.ArtifactID, Version: r.Version, Generation: generation, VerifiedAt: r.VerifiedAt.Time}
		return json.Unmarshal(r.MaterialBindings, &out.Materials)
	})
	return
}
