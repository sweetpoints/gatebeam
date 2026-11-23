package application

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"time"
)

type Audit interface {
	Append(transaction.Scope, audit.Event) error
}
type Management struct {
	Tx       transaction.Runner
	Security Security
	Repo     ChannelRepository
	Sealer   Sealer
	Audit    Audit
	NewID    func() string
}

func (m *Management) Save(ctx context.Context, a ActorRef, c Channel, expected int64, secret []byte) (out Channel, err error) {
	if m.Sealer == nil {
		return out, domain.ErrDenied
	}
	if expected < 0 || (expected == 0 && c.ID != "") || (expected > 0 && c.ID == "") || len(secret) > 4096 {
		return out, domain.ErrInvalid
	}
	c.OwnerID = a.UserID
	if c.Validate() != nil {
		return out, domain.ErrInvalid
	}
	if expected == 0 {
		c.ID = m.NewID()
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = m.Security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := m.Security.ReadWithin(sc, a); e != nil {
			return e
		}
		if e := m.Security.GuardWithin(sc); e != nil {
			return e
		}
		if expected > 0 {
			previous, e := m.Repo.ChannelWithin(sc, c.ID)
			if e != nil {
				return e
			}
			c.OwnerID = previous.OwnerID
			c.Secret = previous.Secret
		}
		if c.Enabled {
			if e := m.Security.DeliveryWithin(sc, c, Event{Kind: "channel_test"}); e != nil {
				return e
			}
		}
		if len(secret) > 0 {
			var e error
			c.Secret, e = m.Sealer.Seal("notification/channel/"+c.ID, secret)
			if e != nil {
				return domain.ErrInvalid
			}
		}
		if len(c.Secret) == 0 {
			return domain.ErrInvalid
		}
		var e error
		out, e = m.Repo.SaveChannelWithin(sc, c, expected)
		if e != nil {
			return e
		}
		body, _ := json.Marshal(map[string]any{"channel_id": c.ID, "revision": out.Revision, "enabled": c.Enabled})
		return m.Audit.Append(sc, audit.Event{ID: m.NewID(), ActorID: a.UserID, Action: "notification.channel.updated", Payload: body})
	})
	return
}
func (m *Management) List(ctx context.Context, a ActorRef) (out []Channel, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = m.Tx.Within(ctx, func(sc transaction.Scope) error {
		if e := m.Security.ReadWithin(sc, a); e != nil {
			return e
		}
		var e error
		out, e = m.Repo.ChannelsWithin(sc)
		return e
	})
	return
}
func (m *Management) Test(ctx context.Context, a ActorRef, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return m.Security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := m.Security.ReadWithin(sc, a); e != nil {
			return e
		}
		if _, e := m.Repo.ChannelWithin(sc, id); e != nil {
			return e
		}
		if e := m.Repo.TestWithin(sc, id); e != nil {
			return e
		}
		body, _ := json.Marshal(map[string]string{"channel_id": id})
		return m.Audit.Append(sc, audit.Event{ID: m.NewID(), ActorID: a.UserID, Action: "notification.channel.test_queued", Payload: body})
	})
}

// Activity requires a current interactive administrator. Public records contain
// fixed outcome codes and the source identity only, never channel ciphertext.
func (m *Management) Activity(ctx context.Context, a ActorRef) (out ActivityView, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = m.Tx.Within(ctx, func(sc transaction.Scope) error {
		if e := m.Security.ReadWithin(sc, a); e != nil {
			return e
		}
		repository, ok := m.Repo.(ActivityRepository)
		if !ok {
			return domain.ErrNotFound
		}
		out.Incidents = []IncidentView{}
		out.Deliveries = []Activity{}
		incidents, e := repository.IncidentsWithin(sc)
		if e != nil {
			return e
		}
		out.Incidents = append(out.Incidents, incidents...)
		rows, e := repository.ActivityWithin(sc)
		if e != nil {
			return e
		}
		for _, row := range rows {
			// API administrator reads generic incident metadata; site identifiers are
			// omitted here. Detailed site views retain their owning context checks.
			row.Event.ResourceID = ""
			row.Event.Fingerprint = ""
			row.Event.ID = ""
			out.Deliveries = append(out.Deliveries, row)
		}
		return nil
	})
	return
}
