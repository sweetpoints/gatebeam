package domain

import "time"

type Version struct {
	// Populated only from verified X.509 material and the successful worker enrollment.
	IssuerKeyFingerprint string    `json:"issuer_key_fingerprint,omitempty"`
	LeafFingerprint      string    `json:"leaf_fingerprint,omitempty"`
	Serial               string    `json:"serial,omitempty"`
	EnrollmentProvider   string    `json:"enrollment_provider,omitempty"`
	ID                   string    `json:"id"`
	SpecID               string    `json:"spec_id"`
	SpecRevision         int64     `json:"spec_revision"`
	Names                []string  `json:"names"`
	Purpose              string    `json:"purpose"`
	Issuer               string    `json:"issuer"`
	NotBefore            time.Time `json:"not_before"`
	NotAfter             time.Time `json:"not_after"`
	Digest               string    `json:"digest"`
	PrivateMaterialRef   string    `json:"private_material_ref,omitempty"`
	Automatic            bool      `json:"automatic"`
}

func (v Version) Usable(now time.Time) bool {
	return !now.Before(v.NotBefore) && now.Before(v.NotAfter)
}

type Attempt struct {
	Failures    int       `json:"failures"`
	NextAttempt time.Time `json:"next_attempt"`
}

func (a Attempt) Failed(now time.Time) Attempt {
	if a.Failures < 16 {
		a.Failures++
	}
	delay := time.Minute * time.Duration(1<<min(a.Failures-1, 10))
	if delay > 24*time.Hour {
		delay = 24 * time.Hour
	}
	a.NextAttempt = now.Add(delay)
	return a
}
