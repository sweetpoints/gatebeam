package release

import (
	"encoding/json"
	app "gatebeam/internal/modules/deployment/application"
	"gatebeam/internal/modules/deployment/domain"
	"gatebeam/internal/platform/transaction"
)

type Service struct {
	repo Repository
	ids  IDs
}

func New(repo Repository, ids IDs) *Service { return &Service{repo, ids} }
func (s *Service) Digest(in PrepareInput) (string, error) {
	b, e := json.Marshal(struct {
		Snapshot      app.Snapshot     `json:"snapshot"`
		PublishedBase map[string]int64 `json:"published_base"`
	}{in.Snapshot, in.PublishedBase})
	if e != nil {
		return "", e
	}
	return s.repo.Digest(b), nil
}
func (s *Service) PrepareWithin(sc transaction.Scope, in PrepareInput) (Candidate, error) {
	if in.Snapshot.Version != "deployment/v1" || len(in.SelectedSiteIDs) == 0 && len(in.Expected) == 0 {
		return Candidate{}, domain.ErrInvalid
	}
	id, e := s.ids.NewID()
	if e != nil {
		return Candidate{}, e
	}
	digest, e := s.Digest(in)
	if e != nil {
		return Candidate{}, e
	}
	c := Candidate{PublishedBase: in.PublishedBase, State: domain.Prepared, ID: id, Snapshot: in.Snapshot, AffectedSiteIDs: in.AffectedSiteIDs, SelectedSiteIDs: in.SelectedSiteIDs, Expected: in.Expected, InputDigest: digest, Changes: in.Changes}
	if e = s.repo.Save(sc, c); e != nil {
		return Candidate{}, e
	}
	return c, nil
}
func (s *Service) ReadWithin(sc transaction.Scope, id string) (Candidate, error) {
	return s.repo.Read(sc, id)
}
func (s *Service) PublishWithin(sc transaction.Scope, id string) (string, error) {
	v, _, e := s.repo.Queue(sc, id)
	return v, e
}

// QueueWithin distinguishes an existing queue record so audit/enqueue occur once.
func (s *Service) QueueWithin(sc transaction.Scope, id string) (string, bool, error) {
	return s.repo.Queue(sc, id)
}
func (s *Service) ListWithin(sc transaction.Scope, limit, offset int) ([]Candidate, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return nil, domain.ErrInvalid
	}
	return s.repo.List(sc, limit, offset)
}

// ListPageWithin bounds raw rows before authorization and preserves continuation
// even when the caller filters every row. It never scans an unbounded ACL gap.
func (s *Service) ListPageWithin(sc transaction.Scope, limit, offset int) ([]Candidate, bool, error) {
	if limit < 1 || limit > 100 || offset < 0 || offset > 100000 {
		return nil, false, domain.ErrInvalid
	}
	rows, err := s.repo.List(sc, limit+1, offset)
	if err != nil {
		return nil, false, err
	}
	more := len(rows) > limit
	if more {
		if offset+limit > 100000 {
			return nil, false, domain.ErrInvalid
		}
		rows = rows[:limit]
	}
	return rows, more, nil
}
