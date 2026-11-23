// Package domain owns release progression. Queue submission is not traffic activation.
package domain

import "errors"

var ErrInvalid = errors.New("invalid release")
var ErrConflict = errors.New("release input changed")
var ErrNotFound = errors.New("release not found")
var ErrUnavailable = errors.New("release security materials unavailable")

type State string

const (
	Prepared      State = "prepared"
	Queued        State = "queued"
	Preparing     State = "preparing"
	Validated     State = "validated"
	Applying      State = "applying"
	Verifying     State = "verifying"
	Succeeded     State = "succeeded"
	Failed        State = "failed"
	Restoring     State = "restoring"
	Restored      State = "restored"
	RestoreFailed State = "restore_failed"
)

type Release struct {
	ID    string
	State State
}

func (r Release) Effective() bool { return r.State == Succeeded }
func (r *Release) Transition(next State) error {
	allowed := map[State][]State{Queued: {Preparing, Failed}, Preparing: {Validated, Failed}, Validated: {Applying, Failed}, Applying: {Verifying, Restoring}, Verifying: {Succeeded, Restoring}, Restoring: {Restored, RestoreFailed}}
	for _, s := range allowed[r.State] {
		if s == next {
			r.State = next
			return nil
		}
	}
	return ErrInvalid
}
