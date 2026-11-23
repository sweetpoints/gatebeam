package domain

import "time"

type Session struct {
	ID, AccountID, TokenHash, CSRFHash string
	AuthVersion                        int64
	Expires                            time.Time
	Revoked                            bool
}

func (s Session) Validate(a Account, now time.Time) error {
	if a.CanManage() != nil || s.AccountID != a.ID || s.AuthVersion != a.AuthVersion || s.Revoked || !now.Before(s.Expires) {
		return ErrDenied
	}
	return nil
}
