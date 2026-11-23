package domain

import (
	"slices"
	"time"
)

type Challenge struct {
	Revision                int64
	ID, Name, Token, Status string
	Validated               time.Time
}
type Order struct {
	ID, AccountID, Directory, Status string
	Names                            []string
	Usage                            Usage
	Expires                          time.Time
	Challenges                       []Challenge
	Revision                         int64
}

func NewOrder(id, account string, p Principal, names []string, challenges []Challenge, now time.Time) (Order, error) {
	o := Order{ID: id, AccountID: account, Directory: p.Directory, Status: "pending", Names: slices.Clone(names), Usage: p.Usage, Expires: now.Add(time.Hour), Challenges: challenges, Revision: 1}
	if id == "" || account == "" || len(challenges) != len(names) || o.Authorize(p, now) != nil {
		return Order{}, ErrPolicy
	}
	if o.Expires.After(p.Expires) {
		o.Expires = p.Expires
	}
	for i, c := range challenges {
		if c.ID == "" || c.Token == "" || c.Name != names[i] || c.Status != "pending" {
			return Order{}, ErrPolicy
		}
	}
	return o, nil
}
func (o Order) Authorize(p Principal, now time.Time) error {
	if p.Authorize(o.Directory, now) != nil || p.Usage != o.Usage {
		return ErrPolicy
	}
	policy, e := NewPolicy(p.Names, p.Usage)
	if e != nil {
		return e
	}
	return policy.Authorize(o.Names)
}
func (o Order) Ready(now time.Time) error {
	if o.Status != "ready" || !now.Before(o.Expires) {
		return ErrPolicy
	}
	for _, c := range o.Challenges {
		if c.Status != "valid" {
			return ErrPolicy
		}
	}
	return nil
}
func (o Order) MatchCSR(names []string) error {
	a, b := slices.Clone(o.Names), slices.Clone(names)
	slices.Sort(a)
	slices.Sort(b)
	if !slices.Equal(a, b) {
		return ErrPolicy
	}
	return nil
}
func (o *Order) CompleteChallenge(id string, valid bool, now time.Time) error {
	if o.Status != "pending" || !now.Before(o.Expires) {
		return ErrPolicy
	}
	found := false
	for i := range o.Challenges {
		c := &o.Challenges[i]
		if c.ID == id {
			if c.Status != "pending" {
				return ErrPolicy
			}
			found = true
			c.Revision++
			c.Status = "invalid"
			if valid {
				c.Status = "valid"
				c.Validated = now
			} else {
				o.Status = "invalid"
			}
		}
	}
	if !found {
		return ErrPolicy
	}
	o.Revision++
	if o.Status != "invalid" {
		o.Status = "ready"
		for _, c := range o.Challenges {
			if c.Status != "valid" {
				o.Status = "pending"
			}
		}
	}
	return nil
}
func (o *Order) Complete(now time.Time) error {
	if e := o.Ready(now); e != nil {
		return e
	}
	o.Status = "valid"
	o.Revision++
	return nil
}
