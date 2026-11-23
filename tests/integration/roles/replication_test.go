//go:build integration

package roles_test

import (
	"bytes"
	"context"
	"encoding/json"
	"gatebeam/internal/modules/certificates"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/modules/identity"
	"gatebeam/internal/modules/notification"
	"gatebeam/internal/modules/pki"
	pkipg "gatebeam/internal/modules/pki/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"github.com/google/uuid"
	"path/filepath"
	"testing"
)

func TestRoleCiphertextWorksAcrossAuthorizedReplicas(t *testing.T) {
	p := testkit.Postgres(t)
	ctx := context.Background()
	type keys struct {
		file, bfile string
		a, b        *secrets.Store
		public      []string
	}
	roles := map[string]keys{}
	for _, role := range []string{"api", "provider", "notification", "ca"} {
		a, b := filepath.Join(t.TempDir(), "a"), filepath.Join(t.TempDir(), "b")
		if e := secrets.EnsureIdentity(a); e != nil {
			t.Fatal(e)
		}
		if e := secrets.EnsureIdentity(b); e != nil {
			t.Fatal(e)
		}
		sa, _ := secrets.New(a)
		sb, _ := secrets.New(b)
		roles[role] = keys{file: a, bfile: b, a: sa, b: sb, public: []string{sa.Recipient(), sb.Recipient()}}
	}
	id := uuid.NewString()
	makeCipher := func(role, label string) []byte {
		t.Helper()
		c, e := roles[role].a.Seal(label, []byte(role+"-historical-secret"))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = roles[role].b.Open(label, c); e == nil {
			t.Fatal("B opened legacy A-only value")
		}
		return c
	}
	totp := makeCipher("api", "identity/totp/"+id)
	if _, e := p.Exec(ctx, `INSERT INTO identity_accounts(id,name,state,auth_version,seed,invite_expires,locked_until,role) VALUES($1,'fixture','active',1,$2,'infinity','-infinity','admin')`, id, totp); e != nil {
		t.Fatal(e)
	}
	providerLabelJSON, _ := json.Marshal([]any{"credential", id, 1})
	providerLabel := "certificates/" + string(providerLabelJSON)
	provider := makeCipher("provider", providerLabel)
	if _, e := p.Exec(ctx, `INSERT INTO certificates_resources(kind,id,revision,enabled) VALUES('credential',$1,1,true)`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO certificates_revisions(kind,id,revision,body,secret) VALUES('credential',$1,1,'{}',$2)`, id, provider); e != nil {
		t.Fatal(e)
	}
	notice := makeCipher("notification", "notification/channel/"+id)
	if _, e := p.Exec(ctx, `INSERT INTO notification_channels(id,owner_id,revision,enabled,metadata,secret) VALUES($1,$1,1,true,'{}',$2)`, id, notice); e != nil {
		t.Fatal(e)
	}
	eab := makeCipher("ca", "pki/eab/"+id)
	if _, e := p.Exec(ctx, `INSERT INTO pki_principals(id,names,purpose,directory,expires) VALUES($1,ARRAY['fixture.test'],'serverAuth','server','infinity');`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO pki_grants(id,principal_id) VALUES($1,$1)`, id); e != nil {
		t.Fatal(e)
	}
	if _, e := p.Exec(ctx, `INSERT INTO pki_eab(id,grant_id,cipher,expires) VALUES($1,$1,$2,'infinity')`, id, eab); e != nil {
		t.Fatal(e)
	}
	rewrap := map[string]func(context.Context, string, []string) (int, error){
		"api": func(ctx context.Context, f string, r []string) (int, error) {
			return identity.RewrapRoleSecrets(ctx, p, f, r)
		},
		"provider": func(ctx context.Context, f string, r []string) (int, error) {
			return certificates.RewrapRoleSecrets(ctx, p, f, r)
		},
		"notification": func(ctx context.Context, f string, r []string) (int, error) {
			return notification.RewrapRoleSecrets(ctx, p, f, r)
		},
		"ca": func(ctx context.Context, f string, r []string) (int, error) {
			return pki.RewrapRoleSecrets(ctx, p, f, r)
		},
	}
	for role, run := range rewrap {
		key := roles[role]
		if n, e := run(ctx, key.file, key.public); e != nil || n != 1 {
			t.Fatalf("%s owner rewrap %d: %v", role, n, e)
		}
	}
	verify := map[string]func(context.Context, string, []string) (int, error){
		"api": func(c context.Context, f string, r []string) (int, error) {
			return identity.VerifyRoleSecrets(c, p, f, r)
		},
		"provider": func(c context.Context, f string, r []string) (int, error) {
			return certificates.VerifyRoleSecrets(c, p, f, r)
		},
		"notification": func(c context.Context, f string, r []string) (int, error) {
			return notification.VerifyRoleSecrets(c, p, f, r)
		},
		"ca": func(c context.Context, f string, r []string) (int, error) { return pki.VerifyRoleSecrets(c, p, f, r) },
	}
	queries := map[string]string{"api": `SELECT seed FROM identity_accounts WHERE id=$1`, "provider": `SELECT ciphertext FROM certificates_provider_envelopes WHERE id=$1`, "notification": `SELECT secret FROM notification_channels WHERE id=$1`, "ca": `SELECT ciphertext FROM pki_eab_envelopes WHERE id=$1`}
	for role, run := range verify {
		var before, after []byte
		if e := p.QueryRow(ctx, queries[role], id).Scan(&before); e != nil {
			t.Fatal(e)
		}
		key := roles[role]
		if n, e := run(ctx, key.bfile, key.public); e != nil || n != 1 {
			t.Fatal("B historical verification failed", role, n, e)
		}
		if e := p.QueryRow(ctx, queries[role], id).Scan(&after); e != nil || !bytes.Equal(before, after) {
			t.Fatal("verification changed stored ciphertext", role, e)
		}
	}
	outputs := map[string][]byte{}
	if e := p.QueryRow(ctx, `SELECT seed FROM identity_accounts WHERE id=$1`, id).Scan(&totp); e != nil {
		t.Fatal(e)
	}
	outputs["api"] = totp
	if e := p.QueryRow(ctx, `SELECT secret FROM notification_channels WHERE id=$1`, id).Scan(&notice); e != nil {
		t.Fatal(e)
	}
	outputs["notification"] = notice
	if e := postgres.NewRunner(p).Within(ctx, func(sc transaction.Scope) error {
		record, e := certpg.New().Read(sc, "credential", id, 1)
		if e != nil {
			return e
		}
		outputs["provider"] = record.Secret
		binding, e := pkipg.New().Binding(sc, id)
		outputs["ca"] = binding.Cipher
		return e
	}); e != nil {
		t.Fatal(e)
	}
	labels := map[string]string{"api": "identity/totp/" + id, "provider": providerLabel, "notification": "notification/channel/" + id, "ca": "pki/eab/" + id}
	for role, cipher := range outputs {
		plain, e := roles[role].b.Open(labels[role], cipher)
		if e != nil || string(plain) != role+"-historical-secret" {
			t.Fatalf("%s B cannot read actual owner row: %v", role, e)
		}
		for other, key := range roles {
			if other != role {
				if _, e = key.b.Open(labels[role], cipher); e == nil {
					t.Fatalf("%s read %s", other, role)
				}
			}
		}
	}
	// Logical immutable records and binding consumption were not rewritten.
	var original []byte
	var consumed bool
	if e := p.QueryRow(ctx, `SELECT cipher,consumed FROM pki_eab WHERE id=$1`, id).Scan(&original, &consumed); e != nil || consumed || string(original) != string(eab) {
		t.Fatalf("EAB logical binding changed: %v", e)
	}
	if e := p.QueryRow(ctx, `SELECT secret FROM certificates_revisions WHERE kind='credential' AND id=$1`, id).Scan(&original); e != nil || string(original) != string(provider) {
		t.Fatalf("provider immutable revision changed: %v", e)
	}
}
