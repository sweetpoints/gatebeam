package nodes

import (
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/audit"
	"gatebeam/internal/platform/transaction"
	"regexp"
	"slices"
	"strings"
	"time"
)

var ErrIdentity = errors.New("node incarnation or connection identity denied")
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var imageDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var token = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,128}$`)
var roles = []string{"nginx", "management", "background-jobs", "log-query"}

type Service struct {
	audit Audit
	ids   IDs
	repo  Repository
	now   func() time.Time
}

func New(repo Repository, now func() time.Time) *Service { return &Service{repo: repo, now: now} }
func uuid(v string) bool                                 { return (domain.NodeRef{ID: v, Epoch: 1}).Valid() }
func (s *Service) RegisterWithin(sc transaction.Scope, r NodeRegistration) (domain.NodeRef, error) {
	if !r.Node.Valid() || len(r.Principal) == 0 || len(r.Principal) > 63 || strings.ContainsAny(r.Principal, "\x00\r\n") || r.RuntimeProtocol != 1 || r.BootFormat != domain.BootFormat || !digest.MatchString(r.BootArtifactID) || len(r.BridgeImages) != len(roles) || len(r.RoleProtocols) != len(roles) {
		return domain.NodeRef{}, domain.ErrInvalid
	}
	for _, role := range roles {
		if !imageDigest.MatchString(r.BridgeImages[role]) || r.RoleProtocols[role] != 1 {
			return domain.NodeRef{}, domain.ErrInvalid
		}
	}
	if r.Original != nil && (r.Original.Node != r.Node || r.Original.ArtifactID != r.BootArtifactID || !validObservation(*r.Original) || r.Original.State != "succeeded") {
		return domain.NodeRef{}, domain.ErrInvalid
	}
	ref, err := s.repo.RegisterNode(sc, r)
	if err == nil {
		err = s.recordAdmin(sc, "deployment.node.registered", r.Node)
	}
	return ref, err
}
func (s *Service) ActivateWithin(sc transaction.Scope, refs []domain.NodeRef) error {
	if err := validateActivationRefs(refs); err != nil {
		return err
	}
	if err := s.repo.ActivateNodes(sc, refs); err != nil {
		return err
	}
	return s.recordAdmin(sc, "deployment.nodes.activated", refs)
}
func validateActivationRefs(refs []domain.NodeRef) error {
	if len(refs) == 0 || len(refs) > domain.MaxFleetNodes {
		return domain.ErrInvalid
	}
	seen := make(map[string]bool, len(refs))
	for _, ref := range refs {
		if !ref.Valid() || seen[ref.ID] {
			return domain.ErrInvalid
		}
		seen[ref.ID] = true
	}
	return nil
}
func (s *Service) SetStatusWithin(sc transaction.Scope, node domain.NodeRef, status string) error {
	if !node.Valid() || !slices.Contains([]string{"active", "quarantined", "revoked"}, status) {
		return domain.ErrInvalid
	}
	if err := s.repo.SetNodeStatus(sc, node, status); err != nil {
		return err
	}
	return s.recordAdmin(sc, "deployment.node."+status, node)
}
func (s *Service) AuthenticateWithin(sc transaction.Scope, node domain.NodeRef) error {
	if !node.Valid() {
		return ErrIdentity
	}
	return s.repo.AuthenticateNode(sc, node)
}
func (s *Service) TargetsWithin(sc transaction.Scope) ([]domain.NodeRef, error) {
	return s.repo.ActiveNodeTargets(sc)
}
func (s *Service) SetDesiredWithin(sc transaction.Scope, id string) ([]domain.NodeRef, error) {
	if !uuid(id) {
		return nil, domain.ErrInvalid
	}
	targets, err := s.repo.ActiveNodeTargets(sc)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, domain.ErrUnavailable
	}
	if err = s.repo.SetNodeDesired(sc, id, targets); err != nil {
		return nil, err
	}
	return targets, nil
}
func validObservation(o Observation) bool {
	if !uuid(o.EventID) || !o.Node.Valid() || !uuid(o.ReleaseID) || !imageDigest.MatchString(o.ImageDigest) || o.ObservedAt.IsZero() {
		return false
	}
	if !slices.Contains([]string{"succeeded", "failed", "restored", "restore_failed", "restricted"}, o.State) {
		return false
	}
	return (o.State != "succeeded" && o.State != "restricted") || (digest.MatchString(o.ArtifactID) && token.MatchString(o.Generation))
}
func (s *Service) ReportWithin(sc transaction.Scope, o Observation) error {
	if !validObservation(o) || o.ObservedAt.After(s.now().Add(30*time.Second)) || o.NodeState != "" {
		return domain.ErrInvalid
	}
	o.ObservedAt = o.ObservedAt.UTC().Round(0)
	return s.repo.ReportNode(sc, o)
}
func (s *Service) ListWithin(sc transaction.Scope, id string) ([]Observation, error) {
	if !uuid(id) {
		return nil, domain.ErrInvalid
	}
	return s.repo.ListNodeObservations(sc, id)
}
func (s *Service) CurrentWithin(sc transaction.Scope, node domain.NodeRef) (Observation, error) {
	if !node.Valid() {
		return Observation{}, ErrIdentity
	}
	return s.repo.CurrentNodeObservation(sc, node)
}
func (s *Service) SummaryWithin(sc transaction.Scope, id string) (Summary, error) {
	rows, err := s.ListWithin(sc, id)
	if err != nil {
		return Summary{}, err
	}
	summary := Summary{Expected: len(rows), Nodes: rows, State: "queued"}
	for _, row := range rows {
		if row.NodeState != "active" {
			summary.Degraded = true
		}
		switch row.State {
		case "succeeded":
			summary.Succeeded++
		case "failed", "restored", "restore_failed":
			summary.Failed++
		}
	}
	summary.Complete = summary.Expected > 0 && summary.Succeeded == summary.Expected && !summary.Degraded
	switch {
	case summary.Complete:
		summary.State = "succeeded"
	case summary.Degraded:
		summary.State = "degraded"
	case summary.Succeeded > 0:
		summary.State = "partial_success"
	case summary.Expected > 0 && summary.Failed == summary.Expected:
		summary.State = "failed"
	}
	return summary, nil
}

func (s *Service) AuthorizeRuntimeWithin(sc transaction.Scope, node domain.NodeRef, image string) error {
	if !node.Valid() || !imageDigest.MatchString(image) {
		return ErrIdentity
	}
	return s.repo.AuthenticateNodeImage(sc, node, image)
}
func (s *Service) RequireDesiredWithin(sc transaction.Scope, node domain.NodeRef, id string) error {
	if !node.Valid() || !uuid(id) {
		return domain.ErrInvalid
	}
	return s.repo.RequireDesiredNode(sc, node, id)
}

// SetAudit binds the administrator command journal during assembly only.
func (s *Service) SetAudit(writer Audit, ids IDs) { s.audit = writer; s.ids = ids }
func (s *Service) recordAdmin(sc transaction.Scope, action string, value any) error {
	if s.audit == nil {
		return nil
	}
	if s.ids == nil {
		return domain.ErrUnavailable
	}
	principal, err := s.repo.NodeManagementPrincipal(sc)
	if err != nil {
		return err
	}
	id, err := s.ids.NewID()
	if err != nil {
		return err
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.audit.Append(sc, audit.Event{ID: id, Action: action, ActorID: "db:" + principal, Payload: payload})
}

// RecipientWithin deliberately uses an optional rollout capability so legacy
// protocol-zero repositories cannot accidentally invent a recipient binding.
func (s *Service) RecipientWithin(sc transaction.Scope, ref domain.NodeRef, role string) (string, error) {
	if !ref.Valid() {
		return "", ErrIdentity
	}
	repo, ok := s.repo.(interface {
		NodeRecipientWithin(transaction.Scope, domain.NodeRef, string) (string, error)
	})
	if !ok {
		return "", ErrIdentity
	}
	return repo.NodeRecipientWithin(sc, ref, role)
}

func (s *Service) AuthorizeLegacyMappingWithin(sc transaction.Scope, node string) error {
	if !uuid(node) {
		return ErrIdentity
	}
	r, ok := s.repo.(interface {
		AuthorizeLegacyMappingWithin(transaction.Scope, string) error
	})
	if !ok {
		return ErrIdentity
	}
	return r.AuthorizeLegacyMappingWithin(sc, node)
}

func (s *Service) ActivateVerifiedWithin(sc transaction.Scope, proof []ActivationProbe) error {
	refs := make([]domain.NodeRef, 0, len(proof))
	for _, p := range proof {
		refs = append(refs, p.Node)
		if !digest.MatchString(p.ArtifactID) || !token.MatchString(p.Generation) || len(p.Images) != len(roles) {
			return domain.ErrInvalid
		}
		for _, role := range roles {
			if !imageDigest.MatchString(p.Images[role]) {
				return domain.ErrInvalid
			}
		}
	}
	if err := validateActivationRefs(refs); err != nil {
		return err
	}
	r, ok := s.repo.(interface {
		VerifyNodeActivationWithin(transaction.Scope, []ActivationProbe) error
	})
	if !ok {
		return domain.ErrUnavailable
	}
	if e := r.VerifyNodeActivationWithin(sc, proof); e != nil {
		return e
	}
	return s.ActivateWithin(sc, refs)
}

func (s *Service) ReadRoleRecipientWithin(sc transaction.Scope, ref domain.NodeRef, role string) (string, error) {
	if !ref.Valid() {
		return "", ErrIdentity
	}
	r, ok := s.repo.(interface {
		ReadRoleRecipientWithin(transaction.Scope, domain.NodeRef, string) (string, error)
	})
	if !ok {
		return "", ErrIdentity
	}
	return r.ReadRoleRecipientWithin(sc, ref, role)
}

// ReadTargetsWithin snapshots serving enrollment for standard HTTP-01 clients.
// Final publication continues to use the separately locked TargetsWithin.
func (s *Service) ReadTargetsWithin(sc transaction.Scope) ([]domain.NodeRef, error) {
	r, ok := s.repo.(interface {
		ReadActiveTargetsWithin(transaction.Scope) ([]domain.NodeRef, error)
	})
	if !ok {
		return nil, ErrIdentity
	}
	return r.ReadActiveTargetsWithin(sc)
}
