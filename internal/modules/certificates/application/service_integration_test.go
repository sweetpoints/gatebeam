//go:build integration

package application_test

import (
	"bytes"
	"context"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	certcrypto "gatebeam/internal/modules/certificates/infrastructure/crypto"
	certpg "gatebeam/internal/modules/certificates/infrastructure/postgres"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/jobs"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type security struct{ tx transaction.Runner }

func (s security) Within(ctx context.Context, _ app.ActorRef, fn func(transaction.Scope) error) error {
	return s.tx.Within(ctx, fn)
}
func (security) RequireWithin(transaction.Scope, app.ActorRef, []string) error { return nil }
func (security) GuardWithin(transaction.Scope) error                           { return nil }

type secret struct{}

func (secret) Seal(_ string, b []byte) ([]byte, error) {
	return append([]byte("fixture encrypted:"), b...), nil
}
func (secret) Open(_ string, b []byte) ([]byte, error) {
	if len(b) < 18 {
		return nil, errors.New("cipher")
	}
	return b[18:], nil
}

type failingCA struct{ calls int }

func (c *failingCA) Obtain(context.Context, app.Work) (app.Issuance, error) {
	c.calls++
	return app.Issuance{}, errors.New("owned CA unavailable")
}
func TestFailureBackoffSurvivesServiceRestart(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	repo := certpg.New()
	guard := security{tx}
	crypto := certcrypto.Crypto{}
	management := app.NewManagement(guard, guard, repo, crypto, secret{}, secret{}, audit.New())
	account, e := management.SaveAccount(context.Background(), app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	spec, e := management.SaveSpec(context.Background(), app.ActorRef{}, "", 0, app.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"})
	if e != nil {
		t.Fatal(e)
	}
	ca := &failingCA{}
	service := app.New(tx, repo, guard, crypto, secret{}, ca, jobs.New(p))
	if _, e = service.Ensure(context.Background(), spec.ID); e == nil {
		t.Fatal("failed CA reported success")
	}
	if _, e = service.Ensure(context.Background(), spec.ID); e == nil {
		t.Fatal("retry bypassed backoff")
	}
	if ca.calls != 1 {
		t.Fatalf("failed issuance retried without persisted backoff: %d", ca.calls)
	}
	// Same-spec single writer and persistent backoff survive service recreation.
	service = app.New(tx, repo, guard, crypto, secret{}, ca, jobs.New(p))
	if _, e = service.Renew(context.Background(), spec.ID); e == nil || ca.calls != 1 {
		t.Fatal("new service bypassed failure state", e, ca.calls)
	}
}

type auditFailure struct{}

func (auditFailure) Append(transaction.Scope, audit.Event) error {
	return errors.New("owned audit failure")
}

type waitingCA struct {
	started, finish chan struct{}
	calls           atomic.Int32
}

func (c *waitingCA) Obtain(ctx context.Context, _ app.Work) (app.Issuance, error) {
	c.calls.Add(1)
	close(c.started)
	select {
	case <-c.finish:
	case <-ctx.Done():
	}
	return app.Issuance{}, errors.New("owned CA failure")
}
func TestCertificateManagementAuditRollbackAndSingleWriter(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	repo := certpg.New()
	guard := security{tx}
	crypto := certcrypto.Crypto{}
	identity := filepath.Join(t.TempDir(), "materials.agekey")
	if e := secrets.EnsureIdentity(identity); e != nil {
		t.Fatal(e)
	}
	se, e := secrets.New(identity)
	if e != nil {
		t.Fatal(e)
	}
	failed := app.NewManagement(guard, guard, repo, crypto, se, se, auditFailure{})
	if _, e = failed.SaveCredential(context.Background(), app.ActorRef{}, "", 0, app.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "entry.test"}, []byte("owned-cloudflare-token")); e == nil {
		t.Fatal("audit failure committed secret")
	}
	var count int
	if e = p.QueryRow(context.Background(), "SELECT count(*) FROM certificates_resources").Scan(&count); e != nil || count != 0 {
		t.Fatal("partial management commit", count, e)
	}
	management := app.NewManagement(guard, guard, repo, crypto, se, se, audit.New())
	credential, e := management.SaveCredential(context.Background(), app.ActorRef{}, "", 0, app.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "entry.test"}, []byte("owned-cloudflare-token"))
	if e != nil {
		t.Fatal(e)
	}
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error {
		r, e := repo.Read(sc, "credential", credential.ID, 1)
		if e != nil {
			return e
		}
		if bytes.Contains(r.Secret, []byte("owned-cloudflare-token")) {
			return errors.New("plaintext credential persisted")
		}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
	account, e := management.SaveAccount(context.Background(), app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	spec, e := management.SaveSpec(context.Background(), app.ActorRef{}, "", 0, app.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"})
	if e != nil {
		t.Fatal(e)
	}
	ca := &waitingCA{started: make(chan struct{}), finish: make(chan struct{})}
	service := app.New(tx, repo, guard, crypto, se, ca, jobs.New(p))
	done := make(chan error, 1)
	go func() { _, e := service.Ensure(context.Background(), spec.ID); done <- e }()
	select {
	case <-ca.started:
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not start")
	}
	for range 4 {
		if _, e = service.Ensure(context.Background(), spec.ID); e == nil {
			t.Fatal("second writer accepted")
		}
	}
	close(ca.finish)
	if e = <-done; e == nil || ca.calls.Load() != 1 {
		t.Fatal("single writer violated", e, ca.calls.Load())
	}
	var expired transaction.Scope
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error { expired = sc; return nil }); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Read(expired, "spec", spec.ID, 1); !errors.Is(e, postgres.ErrInvalidScope) {
		t.Fatal("expired scope fell back to pool", e)
	}
}

type restrictedSecurity struct {
	security
	denied string
}

func (s *restrictedSecurity) RequireWithin(_ transaction.Scope, _ app.ActorRef, ids []string) error {
	for _, id := range ids {
		if id == s.denied {
			return errors.New("resource scope denied")
		}
	}
	return nil
}
func TestSpecCannotReuseCredentialOutsideAuthorizedReferences(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	repo := certpg.New()
	guard := &restrictedSecurity{security: security{tx}}
	manager := app.NewManagement(guard, guard, repo, certcrypto.Crypto{}, secret{}, secret{}, audit.New())
	account, e := manager.SaveAccount(context.Background(), app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	credential, e := manager.SaveCredential(context.Background(), app.ActorRef{}, "", 0, app.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "entry.test"}, []byte("secret"))
	if e != nil {
		t.Fatal(e)
	}
	guard.denied = credential.ID
	if _, e = manager.SaveSpec(context.Background(), app.ActorRef{}, "", 0, app.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "dns-01", CredentialIDs: []string{credential.ID}}); e == nil {
		t.Fatal("reused credential outside reference authorization")
	}
}

func TestDurableChallengeReceiptSurvivesRestart(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	guard := security{tx}
	manager := app.NewManagement(guard, guard, certpg.New(), certcrypto.Crypto{}, secret{}, secret{}, audit.New())
	credential, e := manager.SaveCredential(context.Background(), app.ActorRef{}, "", 0, app.DNSCredential{ZoneID: strings.Repeat("a", 32), ZoneName: "entry.test"}, []byte("owned-token"))
	if e != nil {
		t.Fatal(e)
	}
	journal := certpg.NewChallenges(p)
	r := app.ChallengeReceipt{Owner: "owned-attempt", Binding: "public-binding", CredentialID: credential.ID, CredentialRevision: 1, ZoneID: strings.Repeat("a", 32), ZoneName: "entry.test", Name: "_acme-challenge.entry.test", Content: "public-txt", Comment: "owned-marker"}
	if e = journal.Save(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	r.RecordID = "exact-record"
	if e = journal.Save(context.Background(), r); e != nil {
		t.Fatal(e)
	}
	changed := r
	changed.Content = "another-challenge"
	if e = journal.Save(context.Background(), changed); e == nil {
		t.Fatal("ownership rewritten")
	}
	if _, e = p.Exec(context.Background(), "UPDATE certificates_challenges SET created_at=clock_timestamp()-interval '3 minutes'"); e != nil {
		t.Fatal(e)
	}
	restarted := certpg.NewChallenges(p)
	pending, e := restarted.Pending(context.Background())
	if e != nil || len(pending) != 1 || pending[0].Receipt != r || pending[0].Credential.ID != credential.ID {
		t.Fatal("durable receipt lost", e, pending)
	}
	if e = restarted.Complete(context.Background(), r.Owner, r.Binding); e != nil {
		t.Fatal(e)
	}
	pending, e = restarted.Pending(context.Background())
	if e != nil || len(pending) != 0 {
		t.Fatal("completion not durable", e)
	}
}

func TestPreparationDiscoversUnpublishedSpecsAndRespectsBackoff(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	repo := certpg.New()
	guard := security{tx}
	crypto := certcrypto.Crypto{}
	manager := app.NewManagement(guard, guard, repo, crypto, secret{}, secret{}, audit.New())
	account, e := manager.SaveAccount(context.Background(), app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	_, e = manager.SaveSpec(context.Background(), app.ActorRef{}, "", 0, app.Spec{Names: []string{"entry.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"})
	if e != nil {
		t.Fatal(e)
	}
	ca := &failingCA{}
	service := app.New(tx, repo, guard, crypto, secret{}, ca, jobs.New(p))
	if e = service.PrepareCurrent(context.Background()); e == nil || ca.calls != 1 {
		t.Fatal("unpublished material never prepared", e, ca.calls)
	}
	if e = service.PrepareCurrent(context.Background()); e != nil || ca.calls != 1 {
		t.Fatal("preparation bypassed backoff", e, ca.calls)
	}
}

func TestIssuanceLeaseExcludesOtherSpecRevisions(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	repo := certpg.New()
	guard := security{tx}
	crypto := certcrypto.Crypto{}
	manager := app.NewManagement(guard, guard, repo, crypto, secret{}, secret{}, audit.New())
	account, e := manager.SaveAccount(context.Background(), app.ActorRef{}, "", 0, app.ProviderAccount{Provider: "letsencrypt", Email: "owned@example.test"}, nil)
	if e != nil {
		t.Fatal(e)
	}
	spec, e := manager.SaveSpec(context.Background(), app.ActorRef{}, "", 0, app.Spec{Names: []string{"old.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"})
	if e != nil {
		t.Fatal(e)
	}
	next, e := manager.SaveSpec(context.Background(), app.ActorRef{}, spec.ID, 1, app.Spec{Names: []string{"new.test"}, Purpose: "serverAuth", Method: "acme", ProviderID: account.ID, Challenge: "http-01"})
	if e != nil {
		t.Fatal(e)
	}
	firstCA := &waitingCA{started: make(chan struct{}), finish: make(chan struct{})}
	first := app.New(tx, repo, guard, crypto, secret{}, firstCA, jobs.New(p))
	otherCA := &failingCA{}
	second := app.New(tx, repo, guard, crypto, secret{}, otherCA, jobs.New(p))
	done := make(chan error, 1)
	go func() { _, e := first.EnsureRevision(context.Background(), spec.ID, 1); done <- e }()
	select {
	case <-firstCA.started:
	case <-time.After(3 * time.Second):
		t.Fatal("writer missing")
	}
	_, otherError := second.EnsureRevision(context.Background(), next.ID, 2)
	close(firstCA.finish)
	<-done
	if otherError == nil || otherCA.calls != 0 {
		t.Fatal("different revision entered ACME while same spec leased", otherError, otherCA.calls)
	}
	// Failure releases the spec-wide lease while retaining revision-specific backoff.
	if _, e = second.EnsureRevision(context.Background(), next.ID, 2); e == nil || otherCA.calls != 1 {
		t.Fatal("lease not released after failure", e, otherCA.calls)
	}
}

func TestSpecWideLeaseExpiryAndStaleCompletionAreFenced(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	repo := certpg.New()
	guard := security{tx}
	crypto := certcrypto.Crypto{}
	manager := app.NewManagement(guard, guard, repo, crypto, secret{}, secret{}, audit.New())
	spec, e := manager.SaveSpec(context.Background(), app.ActorRef{}, "", 0, app.Spec{Names: []string{"old.test"}, Purpose: "serverAuth", Method: "import"})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = manager.SaveSpec(context.Background(), app.ActorRef{}, spec.ID, 1, app.Spec{Names: []string{"new.test"}, Purpose: "serverAuth", Method: "import"}); e != nil {
		t.Fatal(e)
	}
	claim := func(revision int64, token string, until time.Time) error {
		return tx.Within(context.Background(), func(sc transaction.Scope) error {
			if e := repo.WriteLock(sc); e != nil {
				return e
			}
			_, e := repo.Claim(sc, spec.ID, revision, token, until)
			return e
		})
	}
	if e = claim(1, "expired-writer", time.Now().Add(-time.Second)); e != nil {
		t.Fatal(e)
	}
	if e = claim(2, "current-writer", time.Now().Add(time.Minute)); e != nil {
		t.Fatal("expired spec lease blocked next revision", e)
	}
	work := func(revision int64, token string) app.Work {
		return app.Work{Spec: app.Record{Resource: app.Resource{ID: spec.ID, Revision: revision}}, Token: token}
	}
	old := work(1, "expired-writer")
	current := work(2, "current-writer")
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error {
		if e := repo.WriteLock(sc); e != nil {
			return e
		}
		return repo.Fail(sc, old, old.Attempt.Failed(time.Now()))
	}); e == nil {
		t.Fatal("stale failure released new revision lease")
	}
	versionID, e := crypto.NewID()
	if e != nil {
		t.Fatal(e)
	}
	version := app.StoredVersion{Version: app.Version{ID: versionID, SpecID: spec.ID, SpecRevision: 1}, CertificatePEM: []byte("owned repository fixture"), EncryptedKey: []byte("owned ciphertext fixture")}
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error {
		if e := repo.WriteLock(sc); e != nil {
			return e
		}
		return repo.Commit(sc, old, version)
	}); e == nil {
		t.Fatal("expired completion committed a version")
	}
	if e = claim(1, "contender", time.Now().Add(time.Minute)); e == nil {
		t.Fatal("stale writer released current exclusion")
	}
	version.SpecRevision = 2
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error {
		if e := repo.WriteLock(sc); e != nil {
			return e
		}
		return repo.Commit(sc, current, version)
	}); e != nil {
		t.Fatal("current writer failed commit", e)
	}
	if e = claim(1, "next-old-revision", time.Now().Add(time.Minute)); e != nil {
		t.Fatal("commit did not release spec-wide lease", e)
	}
	if e = tx.Within(context.Background(), func(sc transaction.Scope) error {
		if e := repo.WriteLock(sc); e != nil {
			return e
		}
		w := work(1, "next-old-revision")
		return repo.Fail(sc, w, w.Attempt.Failed(time.Now()))
	}); e != nil {
		t.Fatal(e)
	}
	if e = claim(1, "backoff-bypass", time.Now().Add(time.Minute)); e == nil {
		t.Fatal("revision-specific failure backoff bypassed")
	}
	if e = claim(2, "renew-current", time.Now().Add(time.Minute)); e != nil {
		t.Fatal("old revision backoff blocked unrelated current revision", e)
	}
}
