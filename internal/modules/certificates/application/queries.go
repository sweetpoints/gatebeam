package application

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/certificates/domain"
	"gatebeam/internal/platform/transaction"
	"sort"
	"time"
)

var ErrDenied = domain.ErrDenied

// Lifecycle contains only immutable public metadata and durable retry state.
// A current stored version is not evidence of activation at the edge.
type ActiveBinding struct {
	SpecRevision int64     `json:"spec_revision"`
	VersionID    string    `json:"version_id"`
	Digest       string    `json:"digest"`
	ArtifactID   string    `json:"artifact_id"`
	Version      string    `json:"version"`
	Generation   string    `json:"generation"`
	VerifiedAt   time.Time `json:"verified_at"`
}
type ActiveBindings interface {
	ForSpecWithin(transaction.Scope, string) ([]ActiveBinding, error)
}

// RevisionLifecycle keeps retries attached to their actual immutable spec revision.
type RevisionLifecycle struct {
	Revision       int64      `json:"revision"`
	CurrentVersion string     `json:"current_version,omitempty"`
	Failures       int        `json:"failures"`
	NextAttempt    *time.Time `json:"next_attempt,omitempty"`
	Preparing      bool       `json:"preparing"`
}

func revisionLifecycle(revision int64, state Lifecycle) RevisionLifecycle {
	return RevisionLifecycle{revision, state.CurrentVersion, state.Failures, state.NextAttempt, state.Preparing}
}

type Lifecycle struct {
	Revisions              []RevisionLifecycle `json:"revisions"`
	Active                 []ActiveBinding     `json:"active"`
	Versions               []Version           `json:"versions"`
	CurrentVersion         string              `json:"current_version,omitempty"`
	Failures               int                 `json:"failures"`
	NextAttempt            *time.Time          `json:"next_attempt,omitempty"`
	Preparing              bool                `json:"preparing"`
	PreparationFailures    int                 `json:"preparation_failures"`
	PreparationNextAttempt *time.Time          `json:"preparation_next_attempt,omitempty"`
}
type ResourceView struct {
	Resource
	Lifecycle Lifecycle `json:"lifecycle"`
}
type QueryRepository interface {
	Repository
	Lifecycle(transaction.Scope, Resource) (Lifecycle, error)
}
type Queries struct {
	owner    *Management
	repo     QueryRepository
	bindings ActiveBindings
}

func NewQueries(security Security, graph Graph, repo QueryRepository, bindings ...ActiveBindings) *Queries {
	q := &Queries{owner: NewManagement(security, graph, repo, nil, nil, nil, nil), repo: repo}
	if len(bindings) > 0 {
		q.bindings = bindings[0]
	}
	return q
}
func validKind(kind string) bool {
	return kind == "spec" || kind == "account" || kind == "credential" || kind == "trust"
}
func (q *Queries) List(ctx context.Context, a ActorRef, kind string) (out []ResourceView, err error) {
	if !validKind(kind) {
		return nil, domain.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out = []ResourceView{}
	err = q.owner.security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := q.owner.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := q.repo.ReadLock(sc); e != nil {
			return e
		}
		rows, e := q.repo.List(sc, kind)
		if e != nil {
			return e
		}
		for _, r := range rows {
			if e = q.owner.authorize(sc, a, kind, r.ID); errors.Is(e, domain.ErrDenied) {
				continue
			} else if e != nil {
				return e
			}
			v, e := q.view(sc, r.Resource)
			if e != nil {
				return e
			}
			out = append(out, v)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return
}
func (q *Queries) Read(ctx context.Context, a ActorRef, kind, id string) (out ResourceView, err error) {
	if !validKind(kind) {
		return out, domain.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = q.owner.security.Within(ctx, a, func(sc transaction.Scope) error {
		if e := q.owner.graph.GuardWithin(sc); e != nil {
			return e
		}
		if e := q.repo.ReadLock(sc); e != nil {
			return e
		}
		if e := q.owner.authorize(sc, a, kind, id); e != nil {
			return e
		}
		r, e := q.repo.Read(sc, kind, id, 0)
		if e != nil {
			return e
		}
		out, e = q.view(sc, r.Resource)
		return e
	})
	if err != nil {
		return ResourceView{}, err
	}
	return
}
func (q *Queries) view(sc transaction.Scope, r Resource) (ResourceView, error) {
	// EAB key IDs are enrollment metadata, never HMAC or account private keys.
	// Body is a validated domain DTO; the repository never reads secret columns.
	if !json.Valid(r.Body) {
		return ResourceView{}, domain.ErrInvalid
	}
	state, e := q.repo.Lifecycle(sc, r)
	if e != nil {
		return ResourceView{}, e
	}
	if r.Kind == "spec" && q.bindings != nil {
		state.Active, e = q.bindings.ForSpecWithin(sc, r.ID)
		if e != nil {
			return ResourceView{}, e
		}
	}
	if r.Kind == "spec" {
		state.Revisions = []RevisionLifecycle{revisionLifecycle(r.Revision, state)}
		seen := map[int64]bool{r.Revision: true}
		for _, binding := range state.Active {
			if seen[binding.SpecRevision] {
				continue
			}
			seen[binding.SpecRevision] = true
			historical := r
			historical.Revision = binding.SpecRevision
			old, e := q.repo.Lifecycle(sc, historical)
			if e != nil {
				return ResourceView{}, e
			}
			state.Revisions = append(state.Revisions, revisionLifecycle(binding.SpecRevision, old))
		}
		sort.Slice(state.Revisions, func(i, j int) bool { return state.Revisions[i].Revision < state.Revisions[j].Revision })
	}
	for i := range state.Versions {
		state.Versions[i].PrivateMaterialRef = ""
	}
	return ResourceView{r, state}, nil
}
