// Package delivery coordinates short authorization transactions around bounded
// external delivery. An accepted request followed by an unknown commit can be
// duplicated on retry; neither provider is represented as exactly-once.
package delivery

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Service struct {
	Tx       transaction.Runner
	Repo     app.DeliveryRepository
	Security app.Security
	Secrets  app.Opener
	Senders  map[string]app.Sender
}

func (s *Service) Deliver(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	var d domain.Delivery
	var c domain.Channel
	var token string
	var skip string
	err := s.Tx.Within(ctx, func(sc transaction.Scope) error {
		if s.Security == nil {
			return domain.ErrDenied
		}
		if err := s.Security.GuardWithin(sc); err != nil {
			return err
		}
		var err error
		d, c, token, err = s.Repo.ClaimWithin(sc, id)
		if err != nil {
			return err
		}
		if token == "" {
			return nil
		}
		if !c.Enabled {
			skip = "disabled"
		} else if c.Recipient == "" {
			skip = "no_recipient"
		} else if authorization := s.Security.DeliveryWithin(sc, c, d.Event); authorization != nil {
			if !errors.Is(authorization, domain.ErrDenied) {
				return authorization
			}
			skip = "denied"
		}
		if skip != "" {
			return s.Repo.FinishWithin(sc, d, c.Revision, token, skip)
		}
		return nil
	})
	if err != nil || token == "" || skip != "" {
		return err
	}
	// Resolve current ciphertext after the final short authority check. Never
	// include decryption/provider errors in audits or responses.
	secret, err := s.Secrets.Open("notification/channel/"+c.ID, c.Secret)
	if err == nil {
		defer clear(secret)
		sender := s.Senders[c.Kind]
		if sender == nil {
			err = domain.ErrDelivery
		} else {
			err = sender.Send(ctx, c, secret, d.Event.Render())
		}
	}
	status := "sent"
	if err != nil {
		status = "pending"
		if d.Attempt >= 5 {
			status = "failed"
		}
	}
	receipt, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	return s.Tx.Within(receipt, func(sc transaction.Scope) error { return s.Repo.FinishWithin(sc, d, c.Revision, token, status) })
}
func (s *Service) Step(ctx context.Context) error {
	var ids []string
	if err := s.Tx.Within(ctx, func(sc transaction.Scope) error { var err error; ids, err = s.Repo.DueWithin(sc); return err }); err != nil {
		return err
	}
	for _, id := range ids {
		if err := s.Deliver(ctx, id); err != nil {
			return err
		}
	}
	return nil
}
