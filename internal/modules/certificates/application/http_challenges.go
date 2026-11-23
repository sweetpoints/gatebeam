package application

import (
	"context"
	"errors"
	"gatebeam/internal/platform/transaction"
	"regexp"
	"slices"
)

var ErrChallenge = errors.New("HTTP challenge unavailable")
var challengeToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
var challengeAuthorization = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}\.[A-Za-z0-9_-]{1,256}$`)

type HTTPChallenge struct{ Owner, Token, KeyAuthorization string }
type HTTPChallengeRepository interface {
	PrepareWithin(transaction.Scope, HTTPChallenge, []NodeRef) error
	ReadyWithin(transaction.Scope, string, []NodeRef) (bool, error)
	CleanupWithin(transaction.Scope, string) error
	PendingWithin(transaction.Scope, NodeRef) ([]HTTPChallenge, error)
	ResetWithin(transaction.Scope, NodeRef) error
	AcknowledgeWithin(transaction.Scope, NodeRef, []HTTPChallenge) error
}
type HTTPChallengeNodes interface {
	TargetsWithin(transaction.Scope) ([]NodeRef, error)
	CallerWithin(transaction.Scope, NodeRef) error
}
type HTTPChallengeFiles interface {
	Reconcile(context.Context, []HTTPChallenge) error
}
type HTTPChallenges struct {
	tx    transaction.Runner
	repo  HTTPChallengeRepository
	nodes HTTPChallengeNodes
}

func NewHTTPChallenges(tx transaction.Runner, repo HTTPChallengeRepository, nodes HTTPChallengeNodes) *HTTPChallenges {
	return &HTTPChallenges{tx, repo, nodes}
}
func sameTargets(a, b []NodeRef) bool {
	if len(a) != len(b) || len(a) == 0 || len(a) > 32 {
		return false
	}
	seen := map[NodeRef]bool{}
	for _, n := range a {
		if !materialUUID.MatchString(n.ID) || n.Epoch == 0 || seen[n] || !slices.Contains(b, n) {
			return false
		}
		seen[n] = true
	}
	return true
}
func (s *HTTPChallenges) Prepare(ctx context.Context, owner, token, keyAuth string, targets []NodeRef) error {
	if !materialUUID.MatchString(owner) || !challengeToken.MatchString(token) || !challengeAuthorization.MatchString(keyAuth) {
		return ErrChallenge
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		current, e := s.nodes.TargetsWithin(sc)
		if e != nil {
			return e
		}
		if !sameTargets(current, targets) {
			return ErrChallenge
		}
		return s.repo.PrepareWithin(sc, HTTPChallenge{owner, token, keyAuth}, targets)
	})
}
func (s *HTTPChallenges) PrepareCurrent(ctx context.Context, owner, token, keyAuth string) error {
	var targets []NodeRef
	if e := s.tx.Within(ctx, func(sc transaction.Scope) (e error) { targets, e = s.nodes.TargetsWithin(sc); return }); e != nil {
		return e
	}
	return s.Prepare(ctx, owner, token, keyAuth, targets)
}
func (s *HTTPChallenges) Ready(ctx context.Context, owner string) (ready bool, err error) {
	if !materialUUID.MatchString(owner) {
		return false, ErrChallenge
	}
	err = s.tx.Within(ctx, func(sc transaction.Scope) error {
		targets, e := s.nodes.TargetsWithin(sc)
		if e != nil {
			return e
		}
		if !sameTargets(targets, targets) {
			return ErrChallenge
		}
		ready, e = s.repo.ReadyWithin(sc, owner, targets)
		return e
	})
	return
}
func (s *HTTPChallenges) Cleanup(ctx context.Context, owner string) error {
	if !materialUUID.MatchString(owner) {
		return ErrChallenge
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error { return s.repo.CleanupWithin(sc, owner) })
}
func (s *HTTPChallenges) Sync(ctx context.Context, node NodeRef, files HTTPChallengeFiles) error {
	var pending []HTTPChallenge
	if e := s.tx.Within(ctx, func(sc transaction.Scope) (e error) {
		if e = s.nodes.CallerWithin(sc, node); e != nil {
			return e
		}
		if e = s.repo.ResetWithin(sc, node); e != nil {
			return e
		}
		pending, e = s.repo.PendingWithin(sc, node)
		return
	}); e != nil {
		return e
	}
	if e := files.Reconcile(ctx, pending); e != nil {
		return e
	}
	return s.tx.Within(ctx, func(sc transaction.Scope) error {
		if e := s.nodes.CallerWithin(sc, node); e != nil {
			return e
		}
		return s.repo.AcknowledgeWithin(sc, node, pending)
	})
}
