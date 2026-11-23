// Package otp adapts the maintained RFC 6238 implementation, returning the exact consumed step.
package otp

import (
	"gatebeam/internal/modules/identity/domain"
	lib "github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"time"
)

type TOTP struct{}

func New() *TOTP { return &TOTP{} }
func (t *TOTP) Generate(name string) (string, string, error) {
	k, e := totp.Generate(totp.GenerateOpts{Issuer: "Gatebeam", AccountName: name, Period: 30, SecretSize: 20, Digits: lib.DigitsSix, Algorithm: lib.AlgorithmSHA1})
	if e != nil {
		return "", "", e
	}
	return k.Secret(), k.URL(), nil
}
func (t *TOTP) Verify(seed, code string, now time.Time) (int64, error) {
	if len(code) != 6 {
		return 0, domain.ErrDenied
	}
	for _, offset := range []int64{0, -1, 1} {
		step := now.Unix()/30 + offset
		if step < 0 {
			continue
		}
		ok, e := totp.ValidateCustom(code, seed, time.Unix(step*30, 0), totp.ValidateOpts{Period: 30, Skew: 0, Digits: lib.DigitsSix, Algorithm: lib.AlgorithmSHA1})
		if e == nil && ok {
			return step, nil
		}
	}
	return 0, domain.ErrDenied
}
