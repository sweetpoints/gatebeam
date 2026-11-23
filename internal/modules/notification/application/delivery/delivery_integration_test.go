//go:build integration

package delivery_test

import (
	"bytes"
	"context"
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/application/alerts"
	"gatebeam/internal/modules/notification/application/delivery"
	"gatebeam/internal/modules/notification/domain"
	repo "gatebeam/internal/modules/notification/infrastructure/postgres"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"gatebeam/internal/platform/testkit"
	"gatebeam/internal/platform/transaction"
	"path/filepath"
	"strings"
	"testing"
)

func TestDuplicateEventAndRecoveryNotification(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	s := alerts.New(tx, r, r)
	e := alerts.Event{ID: "event1", Kind: "target_health", ResourceID: "target1", Fingerprint: "health", Version: 1, State: "firing"}
	for range 2 {
		if err := s.Emit(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	e.ID = "event2"
	e.Version = 2
	if err := s.Emit(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	e.ID = "event3"
	e.Version = 3
	e.State = "resolved"
	for range 2 {
		if err := s.Emit(t.Context(), e); err != nil {
			t.Fatal(err)
		}
	}
	e.ID = "old"
	e.Version = 2
	e.State = "firing"
	if err := s.Emit(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	var state string
	var n int
	if err := p.QueryRow(t.Context(), `SELECT state FROM notification_incidents`).Scan(&state); err != nil || state != "resolved" {
		t.Fatal(state, err)
	}
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM notification_transitions`).Scan(&n); err != nil || n != 2 {
		t.Fatal(n, err)
	}
}

func TestIncidentAndReceiptRollbackTogether(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	e := domain.Event{ID: "rollback", Kind: "target_health", ResourceID: "target1", Fingerprint: "health", Version: 1, State: "firing"}
	boom := errors.New("injected rollback")
	if err := tx.Within(context.Background(), func(sc transaction.Scope) error {
		if err := r.ApplyWithin(sc, e); err != nil {
			return err
		}
		return boom
	}); !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var n int
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM notification_incidents`).Scan(&n); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if err := alerts.New(tx, r, r).Emit(t.Context(), e); err != nil {
		t.Fatal(err)
	}
	if err := p.QueryRow(t.Context(), `SELECT count(*) FROM notification_incidents`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
}

type security struct{ deny bool }

func (s *security) Within(ctx context.Context, a app.ActorRef, fn func(transaction.Scope) error) error {
	return errors.New("unused")
}
func (s *security) ReadWithin(transaction.Scope, app.ActorRef) error { return nil }
func (s *security) GuardWithin(transaction.Scope) error              { return nil }
func (s *security) DeliveryWithin(transaction.Scope, domain.Channel, domain.Event) error {
	if s.deny {
		return domain.ErrDenied
	}
	return nil
}

type recordSender struct {
	calls    int
	fail     bool
	messages []string
}

func (s *recordSender) Send(_ context.Context, _ domain.Channel, _ []byte, message string) error {
	s.calls++
	s.messages = append(s.messages, message)
	if s.fail {
		return errors.New("SECRET provider body")
	}
	return nil
}
func TestOneChannelFailureDoesNotDuplicateOtherChannel(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	key := filepath.Join(t.TempDir(), "identity")
	if e := secrets.EnsureIdentity(key); e != nil {
		t.Fatal(e)
	}
	crypt, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	tgProvider, smtpProvider, smtpConfig, smtpFail, tgCalls, smtpCalls := localProviders(t)
	for _, kind := range []string{"telegram", "smtp"} {
		c := domain.Channel{ID: kind, OwnerID: "owner", Kind: kind, Enabled: true, System: true, Recipient: "123"}
		if kind == "smtp" {
			c.Host = smtpConfig.Host
			c.Port = smtpConfig.Port
			c.TLSMode = smtpConfig.TLSMode
			c.From = smtpConfig.From
			c.Recipient = smtpConfig.Recipient
			c.Username = smtpConfig.Username
		}
		c.Secret, e = crypt.Seal("notification/channel/"+kind, []byte("123:SECRET"))
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.SaveChannelWithin(sc, c, 0); return e }); e != nil {
			t.Fatal(e)
		}
	}
	e = alerts.New(tx, r, r).Emit(t.Context(), domain.Event{ID: "one", Kind: "log_pipeline", ResourceID: "local-log-volume", Fingerprint: "pipeline", Version: 1, State: "firing", Message: "SECRET raw source"})
	if e != nil {
		t.Fatal(e)
	}

	service := delivery.Service{Tx: tx, Repo: r, Security: &security{}, Secrets: crypt, Senders: map[string]app.Sender{"telegram": tgProvider, "smtp": smtpProvider}}
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	if tgCalls.Load() != 1 || smtpCalls.Load() != 1 {
		t.Fatal(tgCalls.Load(), smtpCalls.Load())
	}
	smtpFail.Store(false)
	if _, e = p.Exec(t.Context(), `UPDATE notification_deliveries SET next_at=clock_timestamp() WHERE status='pending'`); e != nil {
		t.Fatal(e)
	}
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	if tgCalls.Load() != 1 || smtpCalls.Load() != 2 {
		t.Fatal("successful other channel resent", tgCalls.Load(), smtpCalls.Load())
	}
	var raw string
	if e = p.QueryRow(t.Context(), `SELECT string_agg(result,',') FROM notification_attempts`).Scan(&raw); e != nil || strings.Contains(raw, "SECRET") {
		t.Fatal(raw, e)
	}
	var encrypted []byte
	if e = p.QueryRow(t.Context(), `SELECT secret FROM notification_channels LIMIT 1`).Scan(&encrypted); e != nil || bytes.Contains(encrypted, []byte("SECRET")) {
		t.Fatal("plaintext secret persisted", e)
	}
}
func TestNoSecretsOrUnauthorizedSiteDetails(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	c := domain.Channel{ID: "disabled", OwnerID: "owner", Kind: "telegram", Enabled: true, System: true, Recipient: "receiver", Secret: []byte("encrypted")}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.SaveChannelWithin(sc, c, 0); return e }); e != nil {
		t.Fatal(e)
	}
	if e := alerts.New(tx, r, r).Emit(t.Context(), domain.Event{ID: "denied", Kind: "target_health", ResourceID: "SECRET", Fingerprint: "health", Version: 1, State: "firing", Message: "SECRET"}); e != nil {
		t.Fatal(e)
	}
	sender := &recordSender{}
	service := delivery.Service{Tx: tx, Repo: r, Security: &security{deny: true}, Senders: map[string]app.Sender{"telegram": sender}}
	if e := service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	if sender.calls != 0 {
		t.Fatal("unauthorized send")
	}
	var status string
	if e := p.QueryRow(t.Context(), `SELECT status FROM notification_deliveries`).Scan(&status); e != nil || status != "denied" {
		t.Fatal(status, e)
	}
}

type brokenSecurity struct{ security }

func (b *brokenSecurity) DeliveryWithin(transaction.Scope, domain.Channel, domain.Event) error {
	return errors.New("authority database unavailable")
}
func TestAuthorityFailureDoesNotTerminallyDropDelivery(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	c := domain.Channel{ID: "authority", OwnerID: "owner", Kind: "telegram", Enabled: true, System: true, Recipient: "receiver", Secret: []byte("encrypted")}
	if e := tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.SaveChannelWithin(sc, c, 0); return e }); e != nil {
		t.Fatal(e)
	}
	if e := alerts.New(tx, r, r).Emit(t.Context(), domain.Event{ID: "authority", Kind: "log_pipeline", ResourceID: "system", Fingerprint: "pipeline", Version: 1, State: "firing"}); e != nil {
		t.Fatal(e)
	}
	service := delivery.Service{Tx: tx, Repo: r, Security: &brokenSecurity{}}
	if e := service.Step(t.Context()); e == nil {
		t.Fatal("transient authority failure became terminal denial")
	}
	var state string
	if e := p.QueryRow(t.Context(), `SELECT status FROM notification_deliveries`).Scan(&state); e != nil || state != "pending" {
		t.Fatal(state, e)
	}
}

type unknownCommit struct {
	app.DeliveryRepository
	fail bool
}

func (r *unknownCommit) FinishWithin(sc transaction.Scope, d domain.Delivery, revision int64, token, status string) error {
	if r.fail && status == "sent" {
		return errors.New("injected unknown local receipt")
	}
	return r.DeliveryRepository.FinishWithin(sc, d, revision, token, status)
}
func TestAcceptedExternalRequestUnknownCommitCanDuplicate(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	key := filepath.Join(t.TempDir(), "identity")
	if e := secrets.EnsureIdentity(key); e != nil {
		t.Fatal(e)
	}
	crypt, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	cipher, e := crypt.Seal("notification/channel/unknown", []byte("SECRET"))
	if e != nil {
		t.Fatal(e)
	}
	c := domain.Channel{ID: "unknown", OwnerID: "owner", Kind: "telegram", Enabled: true, System: true, Recipient: "receiver", Secret: cipher}
	if e = tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.SaveChannelWithin(sc, c, 0); return e }); e != nil {
		t.Fatal(e)
	}
	if e = alerts.New(tx, r, r).Emit(t.Context(), domain.Event{ID: "unknown", Kind: "log_pipeline", ResourceID: "system", Fingerprint: "pipeline", Version: 1, State: "firing"}); e != nil {
		t.Fatal(e)
	}
	store := &unknownCommit{r, true}
	sender := &recordSender{}
	service := delivery.Service{Tx: tx, Repo: store, Security: &security{}, Secrets: crypt, Senders: map[string]app.Sender{"telegram": sender}}
	if e = service.Step(t.Context()); e == nil || sender.calls != 1 {
		t.Fatal("fault injection failed", e, sender.calls)
	}
	if _, e = p.Exec(t.Context(), `UPDATE notification_deliveries SET deadline=clock_timestamp()-interval '1 second'`); e != nil {
		t.Fatal(e)
	}
	store.fail = false
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	if sender.calls != 2 {
		t.Fatal("unknown-commit retry missing", sender.calls)
	}
	var result string
	if e = p.QueryRow(t.Context(), `SELECT result FROM notification_attempts WHERE attempt=1`).Scan(&result); e != nil || result != "commit_unknown" {
		t.Fatal(result, e)
	}
}

type credentialSender struct {
	expected string
	calls    int
	failed   bool
}

func (s *credentialSender) Send(_ context.Context, _ domain.Channel, secret []byte, _ string) error {
	s.calls++
	if string(secret) != s.expected {
		return errors.New("wrong current credential")
	}
	if s.failed {
		return domain.ErrDelivery
	}
	return nil
}
func TestDeliveryUsesCurrentCredentialsAndEnablement(t *testing.T) {
	p := testkit.Postgres(t)
	tx := postgres.NewRunner(p)
	r := repo.New()
	key := filepath.Join(t.TempDir(), "identity")
	if e := secrets.EnsureIdentity(key); e != nil {
		t.Fatal(e)
	}
	crypt, e := secrets.New(key)
	if e != nil {
		t.Fatal(e)
	}
	c := domain.Channel{ID: "current", OwnerID: "owner", Kind: "telegram", Enabled: true, System: true, Recipient: "receiver"}
	save := func(expected int64, value string) {
		t.Helper()
		c.Secret, e = crypt.Seal("notification/channel/"+c.ID, []byte(value))
		if e != nil {
			t.Fatal(e)
		}
		if e = tx.Within(t.Context(), func(sc transaction.Scope) error { _, e := r.SaveChannelWithin(sc, c, expected); return e }); e != nil {
			t.Fatal(e)
		}
	}
	save(0, "old")
	emit := func(id string, version int64, state string) {
		t.Helper()
		if e = alerts.New(tx, r, r).Emit(t.Context(), domain.Event{ID: id, Kind: "log_pipeline", ResourceID: "system", Fingerprint: "pipeline", Version: version, State: state}); e != nil {
			t.Fatal(e)
		}
	}
	sender := &credentialSender{expected: "old", failed: true}
	service := delivery.Service{Tx: tx, Repo: r, Security: &security{}, Secrets: crypt, Senders: map[string]app.Sender{"telegram": sender}}
	emit("first", 1, "firing")
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	save(1, "new")
	sender.expected = "new"
	sender.failed = false
	if _, e = p.Exec(t.Context(), `UPDATE notification_deliveries SET next_at=clock_timestamp() WHERE status='pending'`); e != nil {
		t.Fatal(e)
	}
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	var status string
	if e = p.QueryRow(t.Context(), `SELECT status FROM notification_deliveries`).Scan(&status); e != nil || status != "sent" {
		t.Fatal("retry did not use current credential", status, e)
	}
	emit("recovered", 2, "resolved")
	c.Enabled = false
	save(2, "new")
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	if sender.calls != 2 {
		t.Fatal("disabled channel sent", sender.calls)
	}
	if e = p.QueryRow(t.Context(), `SELECT status FROM notification_deliveries WHERE transition_id='recovered'`).Scan(&status); e != nil || status != "disabled" {
		t.Fatal(status, e)
	}
	c.Enabled = true
	c.Recipient = ""
	save(3, "new")
	emit("again", 3, "firing")
	if e = service.Step(t.Context()); e != nil {
		t.Fatal(e)
	}
	if sender.calls != 2 {
		t.Fatal("empty recipient sent", sender.calls)
	}
	if e = p.QueryRow(t.Context(), `SELECT status FROM notification_deliveries WHERE transition_id='again'`).Scan(&status); e != nil || status != "no_recipient" {
		t.Fatal(status, e)
	}
}
