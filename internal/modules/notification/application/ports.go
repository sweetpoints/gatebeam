package application

import (
	"context"
	"encoding/json"
	"gatebeam/internal/modules/notification/domain"
	"gatebeam/internal/platform/transaction"
)

type ActorRef struct {
	UserID, CredentialID, CredentialKind string
	AuthVersion                          int64
}
type Security interface {
	GuardWithin(transaction.Scope) error
	Within(context.Context, ActorRef, func(transaction.Scope) error) error
	ReadWithin(transaction.Scope, ActorRef) error
	DeliveryWithin(transaction.Scope, domain.Channel, domain.Event) error
}
type Sealer interface {
	Seal(string, []byte) ([]byte, error)
}
type Opener interface {
	Open(string, []byte) ([]byte, error)
}
type Sender interface {
	Send(context.Context, domain.Channel, []byte, string) error
}

// SourceEvent is the consumer's narrow durable-envelope contract. It carries
// no database types or upstream domain models.
type SourceEvent struct {
	ID, Type, AggregateID string
	Version               int64
	Schema                int
	Payload               json.RawMessage
}
type PendingReader interface {
	PendingWithin(transaction.Scope, string, []string) ([]SourceEvent, error)
}

type Repository interface {
	ApplyWithin(transaction.Scope, domain.Event) error
}

type DeliveryRepository interface {
	ClaimWithin(transaction.Scope, string) (domain.Delivery, domain.Channel, string, error)
	FinishWithin(transaction.Scope, domain.Delivery, int64, string, string) error
	DueWithin(transaction.Scope) ([]string, error)
}
type ChannelRepository interface {
	SaveChannelWithin(transaction.Scope, domain.Channel, int64) (domain.Channel, error)
	ChannelWithin(transaction.Scope, string) (domain.Channel, error)
	ChannelsWithin(transaction.Scope) ([]domain.Channel, error)
	TestWithin(transaction.Scope, string) error
}

type Channel = domain.Channel
type Event = domain.Event

var ErrDenied = domain.ErrDenied

type Activity struct {
	ID        string `json:"id"`
	ChannelID string `json:"channel_id"`
	Status    string `json:"status"`
	Attempt   int    `json:"attempt"`
	Reason    string `json:"reason"`
	Event     Event  `json:"event"`
}
type IncidentView struct {
	Kind       string `json:"kind"`
	State      string `json:"state"`
	Version    int64  `json:"version"`
	LagSeconds int64  `json:"lag_seconds"`
}
type ActivityView struct {
	Incidents  []IncidentView `json:"incidents"`
	Deliveries []Activity     `json:"deliveries"`
}
type ActivityRepository interface {
	ActivityWithin(transaction.Scope) ([]Activity, error)
	IncidentsWithin(transaction.Scope) ([]IncidentView, error)
}
