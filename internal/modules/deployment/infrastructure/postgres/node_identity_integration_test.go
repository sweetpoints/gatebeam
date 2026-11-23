//go:build integration

package postgres_test

import (
	"context"
	"gatebeam/internal/modules/deployment/application/nodes"
	"gatebeam/internal/modules/deployment/domain"
	dep "gatebeam/internal/modules/deployment/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/jackc/pgx/v5"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRegistrationRejectsCopiedEncryptionIdentity(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := t.Context()
	owner := nodes.New(dep.New(), time.Now)
	schema := p.Config().ConnConfig.RuntimeParams["search_path"]
	pub := func(label string) string {
		file := filepath.Join(t.TempDir(), label)
		if e := secrets.EnsureIdentity(file); e != nil {
			t.Fatal(e)
		}
		s, e := secrets.New(file)
		if e != nil {
			t.Fatal(e)
		}
		return s.Recipient()
	}
	shared := pub("a")
	images := map[string]string{}
	protocols := map[string]uint32{}
	for _, role := range domain.NodeRoleNames() {
		images[role] = "sha256:" + strings.Repeat("a", 64)
		protocols[role] = 1
	}
	regs := []nodes.NodeRegistration{}
	for i, id := range []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		principal := schema + string(rune('a'+i))
		q := pgx.Identifier{principal}.Sanitize()
		if _, e := p.Exec(ctx, `CREATE ROLE `+q+` LOGIN`); e != nil {
			t.Fatal(e)
		}
		t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP ROLE `+q) })
		regs = append(regs, nodes.NodeRegistration{Node: domain.NodeRef{ID: id, Epoch: 1}, Principal: principal, EncryptionRecipients: map[string]string{"leaf": shared}, RuntimeProtocol: 1, BootFormat: 1, BootArtifactID: strings.Repeat("b", 64), BridgeImages: images, RoleProtocols: protocols})
	}
	register := func(r nodes.NodeRegistration) error {
		return postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error { _, e := owner.RegisterWithin(sc, r); return e })
	}
	if e := register(regs[0]); e != nil {
		t.Fatal(e)
	}
	if e := register(regs[1]); e == nil {
		t.Fatal("B copied A's age identity")
	}
	regs[1].EncryptionRecipients = map[string]string{"leaf": pub("b")}
	if e := register(regs[1]); e != nil {
		t.Fatal(e)
	}
	proof := []nodes.ActivationProbe{{Node: regs[0].Node, ArtifactID: strings.Repeat("b", 64), Generation: "initial", Images: images}, {Node: regs[1].Node, ArtifactID: strings.Repeat("b", 64), Generation: "initial", Images: images}}
	proof[1].ArtifactID = strings.Repeat("c", 64)
	activate := func() error {
		return postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error { return owner.ActivateVerifiedWithin(sc, proof) })
	}
	if e := activate(); e == nil {
		t.Fatal("unconfirmed bootstrap artifact activated")
	}
	var enabled bool
	if e := p.QueryRow(ctx, `SELECT coalesce(bool_or(enabled),false) FROM deployment_nodes`).Scan(&enabled); e != nil || enabled {
		t.Fatal("partial activation before full proof", enabled, e)
	}
	proof[1].ArtifactID = strings.Repeat("b", 64)
	if e := activate(); e != nil {
		t.Fatal(e)
	}
	regs[1].Node.Epoch = 2
	if e := register(regs[1]); e == nil {
		t.Fatal("replacement reused old incarnation age identity")
	}
	regs[1].EncryptionRecipients = map[string]string{"leaf": pub("replacement")}
	if e := register(regs[1]); e == nil {
		t.Fatal("replacement reused old DB principal")
	}
	principal := regs[1].Principal + "_next"
	q := pgx.Identifier{principal}.Sanitize()
	if _, e := p.Exec(ctx, `CREATE ROLE `+q+` LOGIN`); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _, _ = p.Exec(context.Background(), `DROP ROLE `+q) })
	regs[1].Principal = principal
	if e := register(regs[1]); e != nil {
		t.Fatal(e)
	}
}
