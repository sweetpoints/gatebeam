package domain

import "time"

// Principal is the current, explicitly authorized enrollment identity. Its
// lifetime is independent of the short-lived, single-use binding credential.
type Principal struct {
	ID        string    `json:"id"`
	Names     []string  `json:"names"`
	Usage     Usage     `json:"purpose"`
	Directory string    `json:"directory"`
	Expires   time.Time `json:"expires"`
	Disabled  bool      `json:"disabled"`
}

func (p Principal) Validate(now time.Time) error {
	if p.ID == "" || !now.Before(p.Expires) || (p.Directory != "server" && p.Directory != "client") || (p.Directory == "server" && p.Usage != ServerAuth) || (p.Directory == "client" && p.Usage != ClientAuth) {
		return ErrPolicy
	}
	_, e := NewPolicy(p.Names, p.Usage)
	return e
}
func (p Principal) Authorize(directory string, now time.Time) error {
	if p.Disabled || directory != p.Directory {
		return ErrPolicy
	}
	return p.Validate(now)
}

type Binding struct {
	ID, PrincipalID string
	Cipher          []byte
	Expires         time.Time
	Consumed        bool
}

func (b *Binding) Consume(p Principal, directory string, now time.Time) error {
	if b.ID == "" || b.PrincipalID != p.ID || b.Consumed || !now.Before(b.Expires) {
		return ErrPolicy
	}
	if e := p.Authorize(directory, now); e != nil {
		return e
	}
	b.Consumed = true
	return nil
}
