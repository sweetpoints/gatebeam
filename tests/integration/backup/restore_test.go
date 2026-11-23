//go:build integration

package backup_test

import (
	"context"
	agefmt "filippo.io/age"
	"gatebeam/internal/integration/recovery"
	"gatebeam/internal/modules/backup/application"
	archive "gatebeam/internal/modules/backup/infrastructure/age"
	"gatebeam/internal/modules/identity/application/auth"
	"gatebeam/internal/modules/identity/infrastructure/credential"
	otp "gatebeam/internal/modules/identity/infrastructure/otp"
	"gatebeam/internal/modules/identity/infrastructure/password"
	identitypg "gatebeam/internal/modules/identity/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	platform "gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp/totp"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (recovery.Snapshot, string, *pgxpool.Pool) {
	t.Helper()
	return fixtureAt(t, 0)
}
func fixtureAt(t *testing.T, version int64) (recovery.Snapshot, string, *pgxpool.Pool) {
	t.Helper()
	var p *pgxpool.Pool
	if version == 0 {
		p = testkit.Postgres(t)
	} else {
		p = testkit.PostgresAt(t, version)
	}
	dir := t.TempDir()
	key, _ := agefmt.GenerateX25519Identity()
	identity := filepath.Join(dir, "offline.key")
	os.WriteFile(identity, []byte(key.String()), 0600)
	caps := filepath.Join(dir, "capsules")
	os.Mkdir(caps, 0700)
	online, _ := agefmt.GenerateX25519Identity()
	onlinefile := filepath.Join(dir, "online.key")
	os.WriteFile(onlinefile, []byte(online.String()), 0600)
	for _, role := range archive.Roles {
		os.Mkdir(filepath.Join(caps, role), 0700)
		if e := archive.ExportCapsule(context.Background(), caps, role, "test-epoch", key.Recipient().String(), capsulePaths(role, onlinefile)); e != nil {
			t.Fatal(e)
		}
	}
	var schema string
	p.QueryRow(context.Background(), "SELECT current_schema()").Scan(&schema)
	role := schema + "_backup"
	if _, e := p.Exec(context.Background(), `CREATE ROLE `+role+` LOGIN PASSWORD 'owned-only';GRANT USAGE ON SCHEMA `+schema+` TO `+role+`;GRANT SELECT ON ALL TABLES IN SCHEMA `+schema+` TO `+role); e != nil {
		t.Fatal(e)
	}
	cfg := p.Config().Copy()
	cfg.ConnConfig.User = role
	cfg.ConnConfig.Password = "owned-only"
	readonly, e := pgxpool.NewWithConfig(context.Background(), cfg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { readonly.Close(); p.Exec(context.Background(), `DROP OWNED BY `+role+`;DROP ROLE `+role) })
	return recovery.Snapshot{DB: readonly, Capsules: caps, Epoch: "test-epoch", Recipient: key.Recipient().String(), Spool: dir}, identity, p
}
func create(t *testing.T, s recovery.Snapshot) application.Artifact {
	t.Helper()
	a, e := s.Export(context.Background())
	if e != nil {
		t.Fatal("fresh consistent encrypted snapshot missing", e)
	}
	return a
}
func TestEncryptedBackupRequiresOfflineRecoveryIdentity(t *testing.T) {
	s, key, _ := fixture(t)
	a := create(t, s)
	r := application.Restorer{Decoder: recovery.Decoder{}}
	report, e := r.Verify(context.Background(), a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	if report.Manifest.Snapshot == "" {
		t.Fatal("missing snapshot provenance")
	}
	wrong, _ := agefmt.GenerateX25519Identity()
	wrongfile := filepath.Join(t.TempDir(), "wrong")
	os.WriteFile(wrongfile, []byte(wrong.String()), 0600)
	if _, e = r.Verify(context.Background(), a.Path, wrongfile); e == nil {
		t.Fatal("wrong recovery key accepted")
	}
	b, _ := os.ReadFile(a.Path)
	b[len(b)/2] ^= 1
	tampered := filepath.Join(t.TempDir(), "tampered.age")
	os.WriteFile(tampered, b, 0600)
	if _, e = r.Verify(context.Background(), tampered, key); e == nil {
		t.Fatal("modified archive accepted")
	}
}
func TestOldSnapshotCannotReviveCredentialsOrRevocations(t *testing.T) {
	s, key, p := fixture(t)
	ctx := context.Background()
	_, e := p.Exec(ctx, `INSERT INTO identity_accounts(id,name,password_hash,state,auth_version,seed,invite_expires,locked_until,role) VALUES('old','old-admin','old-password','active',1,'seed','infinity','-infinity','admin');INSERT INTO identity_tokens VALUES('token','old','digest',1,'{view}','{}','infinity',false)`)
	if e != nil {
		t.Fatal(e)
	}
	hash, e := password.New().Hash("old-password-security-valid")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = p.Exec(ctx, `UPDATE identity_accounts SET password_hash=$1 WHERE id='old'`, hash); e != nil {
		t.Fatal(e)
	}
	a := create(t, s)
	p.Exec(ctx, `UPDATE identity_accounts SET state='disabled',auth_version=auth_version+1;UPDATE identity_tokens SET revoked=true`)
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	r := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	report, e := r.Verify(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Restore(ctx, report, application.Conservative); e != nil {
		t.Fatal(e)
	}
	pc := p.Config().Copy()
	pc.ConnConfig.Database = target.Database
	delete(pc.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, pc)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	t.Cleanup(func() { p.Exec(context.Background(), `DROP DATABASE `+target.Database+` WITH (FORCE)`) })
	var disabled, revoked bool
	if e = restored.QueryRow(ctx, `SELECT state='disabled' AND password_hash='' AND invite_hash='' FROM identity_accounts WHERE id='old'`).Scan(&disabled); e != nil || !disabled {
		t.Fatal("old password/account revived", e)
	}
	restored.QueryRow(ctx, `SELECT revoked FROM identity_tokens WHERE id='token'`).Scan(&revoked)
	if !revoked {
		t.Fatal("old token revived")
	}
	se, e := secrets.New(filepath.Join(target.Output, "api", "identity.agekey"))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(30 * time.Second)
	svc := auth.New(platform.NewRunner(restored), identitypg.New(), audit.New(), password.New(), otp.New(), se, func() time.Time { return now }, credential.New())
	if _, e = svc.BeginLogin(ctx, "old-admin", "old-password-security-valid"); e == nil {
		t.Fatal("restored password permitted old login")
	}
	invite, e := svc.Bootstrap(ctx, "fresh-admin")
	if e != nil {
		t.Fatal("manual fresh bootstrap unavailable", e)
	}
	parsed, e := url.Parse(invite.ProvisioningURI)
	if e != nil {
		t.Fatal(e)
	}
	code, e := totp.GenerateCode(parsed.Query().Get("secret"), now)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = svc.EnrollTOTP(ctx, invite.InviteID, "new-manual-owner-password", code); e != nil {
		t.Fatal("fresh manual enrollment failed", e)
	}
	challenge, e := svc.BeginLogin(ctx, "fresh-admin", "new-manual-owner-password")
	if e != nil {
		t.Fatal("fresh owner login unavailable", e)
	}
	now = now.Add(30 * time.Second)
	code, e = totp.GenerateCode(parsed.Query().Get("secret"), now)
	if e != nil {
		t.Fatal(e)
	}
	session, e := svc.FinishLogin(ctx, challenge.ChallengeID, code)
	if e != nil {
		t.Fatal("fresh owner second factor unavailable", e)
	}
	if _, e = svc.Authenticate(ctx, session.Token); e != nil {
		t.Fatal("fresh owner session unavailable", e)
	}
	if _, e = svc.Bootstrap(ctx, "second-admin"); e == nil {
		t.Fatal("recovery gate reusable")
	}
	if _, e = svc.Bootstrap(ctx, "old-admin"); e == nil {
		t.Fatal("old account reused")
	}
	if strings.Contains(target.Output, "..") || target.Output == "" {
		t.Fatal("missing isolated files")
	}
}
func TestRestoreCannotWriteArbitraryPathsOrOpenPublicIngress(t *testing.T) {
	s, key, p := fixture(t)
	a := create(t, s)
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	r := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	ctx := context.Background()
	report, e := r.Verify(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	forged := report
	forged.Manifest.Epoch = "changed"
	if e = r.Restore(ctx, forged, application.Conservative); e == nil {
		t.Fatal("modified report accepted")
	}
	if e = r.Restore(ctx, report, "activate"); e == nil {
		t.Fatal("public activation accepted")
	}
	if target.Database != "" {
		t.Fatal("invalid request created DB")
	}
	originalDirectory := target.Directory
	outside := t.TempDir()
	link := filepath.Join(t.TempDir(), "symlink")
	if e = os.Symlink(outside, link); e != nil {
		t.Fatal(e)
	}
	target.Directory = link
	if e = r.Restore(ctx, report, application.Conservative); e == nil {
		t.Fatal("symlink destination accepted")
	}
	if target.Database != "" {
		t.Fatal("symlink destination created database")
	}
	target.Directory = originalDirectory
	b, _ := os.ReadFile(a.Path)
	os.WriteFile(a.Path, append(b, 1), 0600)
	if e = r.Restore(ctx, report, application.Conservative); e == nil {
		t.Fatal("source changed after verification accepted")
	}
	entries, _ := os.ReadDir(target.Directory)
	if len(entries) != 0 {
		t.Fatal("denied restore wrote output")
	}

}

func TestBackupSnapshotRejectsWriterRoleAndMissingEpoch(t *testing.T) {
	s, _, p := fixture(t)
	ctx := context.Background()
	unsafe := s
	unsafe.DB = p
	if _, e := unsafe.Export(ctx); e == nil {
		t.Fatal("snapshot exporter accepted admin authority")
	}
	var schema string
	p.QueryRow(ctx, `SELECT current_schema()`).Scan(&schema)
	role := schema + "_backup"
	if _, e := p.Exec(ctx, `GRANT UPDATE(password_hash) ON identity_accounts TO `+role); e != nil {
		t.Fatal(e)
	}
	if _, e := s.Export(ctx); e == nil {
		t.Fatal("snapshot exporter accepted security write capability")
	}
	if _, e := p.Exec(ctx, `REVOKE UPDATE(password_hash) ON identity_accounts FROM `+role); e != nil {
		t.Fatal(e)
	}
	s.Epoch = "missing"
	if _, e := s.Export(ctx); e == nil {
		t.Fatal("snapshot exporter accepted missing capsule epoch")
	}
}

func capsulePaths(role, path string) map[string]string {
	out := map[string]string{}
	for _, n := range archive.AllowedFiles(role) {
		out[n] = path
	}
	return out
}

func TestSnapshotRestoreKeepsHistoricalMaterialIdentityAfterRotation(t *testing.T) {
	s, key, p := fixture(t)
	ctx := context.Background()
	onlinefile := filepath.Join(filepath.Dir(key), "online.key")
	old, e := secrets.New(onlinefile)
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := old.Seal("historical-certificate-key", []byte("owned historical private material"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO certificates_resources VALUES('spec','10000000-0000-4000-8000-000000000001',1,true);INSERT INTO certificates_revisions(kind,id,revision,body) VALUES('spec','10000000-0000-4000-8000-000000000001',1,'{}')`)
	if e != nil {
		t.Fatal(e)
	}
	_, e = p.Exec(ctx, `INSERT INTO certificates_versions(id,spec_id,spec_revision,body,certificate_pem,encrypted_key) VALUES('20000000-0000-4000-8000-000000000002','10000000-0000-4000-8000-000000000001',1,'{}','public-fixture',$1)`, cipher)
	if e != nil {
		t.Fatal(e)
	}
	before, e := archive.ReadCapsules(s.Capsules, s.Epoch, s.Recipient)
	if e != nil {
		t.Fatal(e)
	}
	digest := archive.Digest(before["capsules/edge.age"])
	replacement, _ := agefmt.GenerateX25519Identity()
	os.WriteFile(onlinefile, []byte(replacement.String()), 0600)
	s.Epoch = "rotated"
	for _, role := range archive.Roles {
		if e = archive.ExportCapsule(ctx, s.Capsules, role, s.Epoch, s.Recipient, capsulePaths(role, onlinefile)); e != nil {
			t.Fatal(e)
		}
	}
	a := create(t, s)
	target := &recovery.Destination{Admin: p, Directory: t.TempDir(), Identity: key}
	r := application.Restorer{Decoder: recovery.Decoder{}, Destination: target}
	report, e := r.Verify(ctx, a.Path, key)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.Restore(ctx, report, application.Conservative); e != nil {
		t.Fatal(e)
	}
	cfg := p.Config().Copy()
	cfg.ConnConfig.Database = target.Database
	delete(cfg.ConnConfig.RuntimeParams, "search_path")
	restored, e := pgxpool.NewWithConfig(ctx, cfg)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	defer p.Exec(ctx, `DROP DATABASE `+target.Database+` WITH (FORCE)`)
	var saved []byte
	var enabled bool
	if e = restored.QueryRow(ctx, `SELECT encrypted_key FROM certificates_versions LIMIT 1`).Scan(&saved); e != nil {
		t.Fatal(e)
	}
	restored.QueryRow(ctx, `SELECT enabled FROM certificates_resources LIMIT 1`).Scan(&enabled)
	if enabled {
		t.Fatal("old material reauthorized by key recovery")
	}
	prior, e := secrets.New(filepath.Join(target.Output, "edge", "history", digest, "materials.agekey"))
	if e != nil {
		t.Fatal("historical decryption key not staged", e)
	}
	plain, e := prior.Open("historical-certificate-key", saved)
	if e != nil || string(plain) != "owned historical private material" {
		t.Fatal("historical key no longer decrypts restored material", e)
	}
	current, e := secrets.New(filepath.Join(target.Output, "edge", "materials.agekey"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = current.Open("historical-certificate-key", saved); e == nil {
		t.Fatal("fixture did not exercise distinct rotated key")
	}
}
