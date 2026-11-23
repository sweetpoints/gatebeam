package domain

import "time"

type Challenge struct {
	Hash, AccountID string
	AuthVersion     int64
	Expires         time.Time
	Attempts        int32
	Consumed        bool
}

func (c Challenge) Valid(now time.Time, version int64) error {
	if c.Consumed || c.Attempts >= 5 || version != c.AuthVersion || !now.Before(c.Expires) {
		return ErrDenied
	}
	return nil
}

// Recovery codes are opaque high-entropy values; only digest and consumed state persist.
type Recovery struct{ Consumed bool }

func (r *Recovery) Consume(a Account) error {
	if r.Consumed || a.CanRecover() != nil {
		return ErrDenied
	}
	r.Consumed = true
	return nil
}
