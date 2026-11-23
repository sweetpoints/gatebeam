package application

import (
	"context"
	"gatebeam/internal/platform/transaction"
	"time"
)

type EnrollmentView struct {
	Grant
	BindingState   string     `json:"binding_state"`
	BindingExpires *time.Time `json:"binding_expires,omitempty"`
}
type IssuedView struct {
	Issuer      string     `json:"issuer"`
	Serial      string     `json:"serial"`
	PrincipalID string     `json:"principal_id"`
	Names       []string   `json:"names"`
	Purpose     string     `json:"purpose"`
	NotBefore   time.Time  `json:"not_before"`
	NotAfter    time.Time  `json:"not_after"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	Reason      *int       `json:"reason,omitempty"`
}
type QueryRepository interface {
	Enrollments(transaction.Scope) ([]EnrollmentView, error)
	IssuedMetadata(transaction.Scope) ([]IssuedView, error)
}
type QueryResult struct {
	Enrollments  []EnrollmentView  `json:"enrollments"`
	Certificates []IssuedView      `json:"certificates"`
	Directories  map[string]string `json:"directories"`
}
type Queries struct {
	security    SecurityAction
	repo        QueryRepository
	directories map[string]string
}

func NewQueries(security SecurityAction, repo QueryRepository, directories map[string]string) *Queries {
	return &Queries{security, repo, directories}
}
func (q *Queries) Read(ctx context.Context, a ActorRef) (out QueryResult, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = q.security.Within(ctx, a, func(sc transaction.Scope) error {
		var e error
		out.Enrollments, e = q.repo.Enrollments(sc)
		if e != nil {
			return e
		}
		out.Certificates, e = q.repo.IssuedMetadata(sc)
		out.Directories = q.directories
		return e
	})
	if err != nil {
		return QueryResult{}, err
	}
	return
}
