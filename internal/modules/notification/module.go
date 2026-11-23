// Package notification assembles API public sealing and worker private delivery
// as separate capabilities; neither assembly accepts CA or certificate keys.
package notification

import (
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/application/alerts"
	"gatebeam/internal/modules/notification/application/delivery"
	repo "gatebeam/internal/modules/notification/infrastructure/postgres"
	"gatebeam/internal/modules/notification/infrastructure/smtp"
	"gatebeam/internal/modules/notification/infrastructure/telegram"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/postgres"
	"gatebeam/internal/platform/secrets"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func NewManagement(p *pgxpool.Pool, s app.Security, recipient string, policy ...[]string) (*app.Management, error) {
	var sealer app.Sealer
	if recipient != "" {
		var public []string
		if len(policy) > 0 {
			public = policy[0]
		}
		v, e := secrets.ConfiguredRecipient(recipient, public)
		if e != nil {
			return nil, e
		}
		sealer = v
	}
	return &app.Management{Tx: postgres.NewRunner(p), Security: s, Repo: repo.New(), Sealer: sealer, Audit: audit.New(), NewID: uuid.NewString}, nil
}
func NewWorker(p *pgxpool.Pool, s app.Security, identityFile, recipient string, policy ...[]string) (*alerts.Service, *delivery.Service, error) {
	var public []string
	if len(policy) > 0 {
		public = policy[0]
	}
	secret, e := secrets.ConfiguredStore(identityFile, public)
	if e != nil {
		return nil, nil, e
	}
	if recipient == "" || secret.Recipient() != recipient {
		return nil, nil, errors.New("notification identity does not match recipient")
	}
	tx, r := postgres.NewRunner(p), repo.New()
	return alerts.New(tx, r, r), &delivery.Service{Tx: tx, Repo: r, Security: s, Secrets: secret, Senders: map[string]app.Sender{"telegram": telegram.Sender{}, "smtp": smtp.Sender{}}}, nil
}
