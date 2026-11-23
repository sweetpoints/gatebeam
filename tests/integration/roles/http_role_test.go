//go:build integration

package roles_test

import (
	app "gatebeam/internal/modules/certificates/application"
	repo "gatebeam/internal/modules/certificates/infrastructure/postgres"
	pg "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	fixture "gatebeam/tests/fixtures/deployment"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"testing"
)

func TestPrivateHTTPPublishersCannotForgePeerReady(t *testing.T) {
	p := testkit.Postgres(t)
	roles := fixture.RuntimeRoles(t, p)
	a, b := uuid.NewString(), uuid.NewString()
	for index, id := range []string{a, b} {
		principal := roles["edge"].Name
		if index == 1 {
			principal = "owned_other_edge"
		}
		if _, e := p.Exec(t.Context(), `INSERT INTO deployment_nodes(id,epoch,principal,registration) VALUES($1,1,$2,'{}')`, id, principal); e != nil {
			t.Fatal(e)
		}
	}
	for _, role := range []string{"edge", "api", "ca"} {
		t.Run(role, func(t *testing.T) {
			c := p.Config().Copy()
			c.ConnConfig.User = roles[role].Name
			c.ConnConfig.Password = roles[role].Password
			pool, e := pgxpool.NewWithConfig(t.Context(), c)
			if e != nil {
				t.Fatal(e)
			}
			defer pool.Close()
			owner := uuid.NewString()
			token := "owned-token-" + role
			e = pg.NewRunner(pool).Within(t.Context(), func(sc transaction.Scope) error {
				return repo.NewHTTPChallenges().PrepareWithin(sc, app.HTTPChallenge{Owner: owner, Token: token, KeyAuthorization: "owned.authorization"}, []app.NodeRef{{ID: a, Epoch: 1}, {ID: b, Epoch: 1}})
			})
			if e == nil {
				t.Fatal("private role published an arbitrary external ACME challenge")
			}
			if _, e = p.Exec(t.Context(), `INSERT INTO certificates_http_challenges(owner,token,key_authorization) VALUES($1,$2,'owned.authorization')`, owner, token); e != nil {
				t.Fatal(e)
			}
			if _, e = p.Exec(t.Context(), `INSERT INTO certificates_http_targets(owner,token,node_id,node_epoch) VALUES($1,$2,$3,1)`, owner, token, b); e != nil {
				t.Fatal(e)
			}
			tag, e := pool.Exec(t.Context(), `UPDATE certificates_http_targets SET ready=true WHERE owner=$1 AND node_id=$2`, owner, b)
			if e == nil && tag.RowsAffected() != 0 {
				t.Fatal("private role forged peer HTTP01 ready")
			}
			_, e = pool.Exec(t.Context(), `INSERT INTO certificates_http_targets(owner,token,node_id,node_epoch,ready) VALUES($1,$2,$3,2,true)`, owner, token, b)
			if e == nil {
				t.Fatal("private publisher inserted ready=true")
			}
		})
	}
}
