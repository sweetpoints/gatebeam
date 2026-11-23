package domain

import "time"

type APIToken struct {
	ID, AccountID, Digest string
	AuthVersion           int64
	Actions               []string
	SiteIDs               []string
	Expires               time.Time
	Revoked               bool
}

func (t APIToken) Validate(a Account, now time.Time) error {
	if t.Revoked || !now.Before(t.Expires) || a.CanManage() != nil || a.ID != t.AccountID || a.AuthVersion != t.AuthVersion {
		return ErrDenied
	}
	return nil
}
func (t APIToken) Allows(action Action, sites []string) bool {
	ok := false
	for _, a := range t.Actions {
		if a == string(action) {
			ok = true
		}
	}
	if !ok || len(sites) == 0 {
		return false
	}
	for _, id := range sites {
		found := false
		for _, s := range t.SiteIDs {
			if id == s {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}
