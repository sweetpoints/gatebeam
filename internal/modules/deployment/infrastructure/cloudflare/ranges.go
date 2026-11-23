// Package cloudflare reads official IP ranges over authenticated HTTPS.
package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	edge "gatebeam/internal/modules/deployment/application/runtime"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"time"
)

var ErrRanges = errors.New("official Cloudflare networks unavailable")

type Source struct {
	endpoint string
	client   *http.Client
	ttl      time.Duration
}

func New(endpoint string, client *http.Client, ttl time.Duration) (*Source, error) {
	u, e := url.Parse(endpoint)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || ttl < time.Minute || ttl > 24*time.Hour || client == nil {
		return nil, ErrRanges
	}
	c := *client
	c.Timeout = 5 * time.Second
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Source{endpoint, &c, ttl}, nil
}
func generation(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func (s *Source) Fetch(ctx context.Context, now time.Time) (out edge.CloudflareSet, err error) {
	request, e := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if e != nil {
		return out, ErrRanges
	}
	response, e := s.client.Do(request)
	if e != nil {
		return out, ErrRanges
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return out, ErrRanges
	}
	body, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(body) > 65536 {
		return out, ErrRanges
	}
	var v struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4 *[]string `json:"ipv4_cidrs"`
			IPv6 *[]string `json:"ipv6_cidrs"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &v) != nil || !v.Success || v.Result.IPv4 == nil || v.Result.IPv6 == nil || len(*v.Result.IPv4)+len(*v.Result.IPv6) > 200 {
		return out, ErrRanges
	}
	seen := map[netip.Prefix]bool{}
	for family, values := range [][]string{*v.Result.IPv4, *v.Result.IPv6} {
		for _, raw := range values {
			p, e := netip.ParsePrefix(raw)
			if e != nil || p.Bits() == 0 || p.Addr().Is4() != (family == 0) || p.Masked() != p {
				return edge.CloudflareSet{}, ErrRanges
			}
			if !seen[p] {
				out.Networks = append(out.Networks, p)
				seen[p] = true
			}
		}
	}
	sort.Slice(out.Networks, func(i, j int) bool { return out.Networks[i].String() < out.Networks[j].String() })
	out.ValidUntil = now.Add(s.ttl)
	out.Generation = generation(out)
	return out, nil
}

// Refresh distinguishes a bounded, still-valid cache from authoritative removal
// or expiry. Expiry yields a real empty generation, allowing a closed-site reload.
func (s *Source) Refresh(ctx context.Context, old edge.CloudflareSet, now time.Time) (edge.CloudflareSet, error) {
	fresh, e := s.Fetch(ctx, now)
	if e == nil {
		return fresh, nil
	}
	if old.Generation != "" && now.Before(old.ValidUntil) {
		return old, nil
	}
	closed := edge.CloudflareSet{ValidUntil: old.ValidUntil}
	closed.Generation = generation(struct {
		Previous time.Time
		Closed   bool
	}{old.ValidUntil, true})
	return closed, nil
}
