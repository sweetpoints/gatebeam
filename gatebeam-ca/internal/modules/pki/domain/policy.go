package domain

import (
	"errors"
	"net/netip"
	"strings"
)

var ErrPolicy = errors.New("certificate policy rejected")

type Policy struct {
	names map[string]struct{}
	usage Usage
}

func NewPolicy(names []string, usage Usage) (Policy, error) {
	if len(names) == 0 || len(names) > 100 || (usage != ServerAuth && usage != ClientAuth) {
		return Policy{}, ErrPolicy
	}
	p := Policy{names: map[string]struct{}{}, usage: usage}
	for _, n := range names {
		if !validName(n) {
			return Policy{}, ErrPolicy
		}
		if _, ok := p.names[n]; ok {
			return Policy{}, ErrPolicy
		}
		p.names[n] = struct{}{}
	}
	return p, nil
}
func validName(n string) bool {
	if len(n) > 253 || !strings.Contains(n, ".") || strings.ToLower(n) != n {
		return false
	}
	if _, e := netip.ParseAddr(n); e == nil {
		return false
	}
	for _, label := range strings.Split(n, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func (p Policy) Usage() Usage { return p.usage }
func (p Policy) Authorize(names []string) error {
	if len(names) == 0 || len(names) > 100 || len(p.names) == 0 {
		return ErrPolicy
	}
	seen := map[string]bool{}
	for _, n := range names {
		if _, ok := p.names[n]; !ok || seen[n] {
			return ErrPolicy
		}
		seen[n] = true
	}
	return nil
}
