package certificatematerials

import (
	"errors"
	cert "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
)

type RecipientNodes interface {
	AuthenticateWithin(transaction.Scope, domain.NodeRef) error
	RecipientWithin(transaction.Scope, domain.NodeRef, string) (string, error)
}
type NodeAuthority struct{ Nodes RecipientNodes }

func (a NodeAuthority) CallerWithin(sc transaction.Scope, n cert.NodeRef) error {
	return a.Nodes.AuthenticateWithin(sc, domain.NodeRef{ID: n.ID, Epoch: n.Epoch})
}
func (a NodeAuthority) TargetWithin(sc transaction.Scope, b cert.RecipientBinding) error {
	recipient, e := a.Nodes.RecipientWithin(sc, domain.NodeRef{ID: b.Node.ID, Epoch: b.Node.Epoch}, "leaf")
	if e != nil {
		return e
	}
	if recipient != b.Recipient {
		return errors.New("registered leaf recipient mismatch")
	}
	return nil
}

// ChallengeNodes maps the current enabled deployment set into certificate-owned
// values. The same registry lock fences membership through Prepare/Ready.
type ChallengeTargets interface {
	RecipientNodes
	TargetsWithin(transaction.Scope) ([]domain.NodeRef, error)
}
type ChallengeNodes struct{ Nodes ChallengeTargets }

func (a ChallengeNodes) TargetsWithin(sc transaction.Scope) (out []cert.NodeRef, err error) {
	targets, err := a.Nodes.TargetsWithin(sc)
	if err != nil {
		return nil, err
	}
	for _, n := range targets {
		out = append(out, cert.NodeRef{ID: n.ID, Epoch: n.Epoch})
	}
	return
}
func (a ChallengeNodes) CallerWithin(sc transaction.Scope, n cert.NodeRef) error {
	return a.Nodes.AuthenticateWithin(sc, domain.NodeRef{ID: n.ID, Epoch: n.Epoch})
}

type ReadOnlyChallengeTargets interface {
	ReadTargetsWithin(transaction.Scope) ([]domain.NodeRef, error)
}
type ReadOnlyChallengeNodes struct{ Nodes ReadOnlyChallengeTargets }

func (a ReadOnlyChallengeNodes) TargetsWithin(sc transaction.Scope) (out []cert.NodeRef, err error) {
	nodes, e := a.Nodes.ReadTargetsWithin(sc)
	if e != nil {
		return nil, e
	}
	for _, n := range nodes {
		out = append(out, cert.NodeRef{ID: n.ID, Epoch: n.Epoch})
	}
	return out, nil
}
func (a ReadOnlyChallengeNodes) CallerWithin(transaction.Scope, cert.NodeRef) error {
	return cert.ErrChallenge
}
