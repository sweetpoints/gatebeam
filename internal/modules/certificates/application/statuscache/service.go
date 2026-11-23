package statuscache

import (
	"bytes"
	"context"
	"errors"
	"gatebeam/internal/modules/certificates/domain"
	"sync"
	"time"
)

var ErrUnsafe = errors.New("OCSP status unavailable or unsafe")

const MaxDER = 64 << 10

type Service struct {
	mu       sync.Mutex
	store    Store
	verifier Verifier
	fetch    Fetcher
}

func New(store Store, verifier Verifier, fetch Fetcher) (*Service, error) {
	if store == nil || verifier == nil {
		return nil, ErrUnsafe
	}
	return &Service{store: store, verifier: verifier, fetch: fetch}, nil
}
func (s *Service) AddIssuers(issuers [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifier.AddIssuers(issuers)
}
func (s *Service) Issuers() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.verifier.Issuers()
}
func (s *Service) SetFetcher(fetch Fetcher) { s.mu.Lock(); defer s.mu.Unlock(); s.fetch = fetch }
func (s *Service) observe(ctx context.Context, r Request, der []byte, now time.Time) error {
	req, err := s.verifier.Request(r)
	if err != nil {
		return err
	}
	verdict, err := s.verifier.Verify(r, der, now)
	if err != nil {
		return err
	}
	revoked, err := s.store.Check(ctx, req.CertKey, now, verdict.Revoked)
	if err != nil || (revoked && !verdict.Revoked) {
		return ErrUnsafe
	}
	return s.store.Save(ctx, req.CacheKey, domain.CachedStatus{DER: bytes.Clone(der), ObservedAt: now})
}
func (s *Service) Observe(ctx context.Context, r Request, der []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.observe(ctx, r, der, now)
}
func (s *Service) Lookup(ctx context.Context, r Request, now time.Time) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req, err := s.verifier.Request(r)
	if err != nil {
		return nil, err
	}
	revoked, err := s.store.Check(ctx, req.CertKey, now, false)
	if err != nil || revoked {
		return nil, ErrUnsafe
	}
	cached, err := s.store.Load(ctx, req.CacheKey)
	if err == nil && !now.Before(cached.ObservedAt) {
		if verdict, e := s.verifier.Verify(r, cached.DER, now); e == nil && verdict.Good {
			return bytes.Clone(cached.DER), nil
		}
	}
	if s.fetch == nil {
		return nil, ErrUnsafe
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	started := time.Now()
	der, err := s.fetch.Fetch(fetchCtx, req.IssuerFingerprint, r.DER)
	observedAt := now.Add(time.Since(started))
	if err != nil || s.observe(ctx, r, der, observedAt) != nil {
		return nil, ErrUnsafe
	}
	verdict, err := s.verifier.Verify(r, der, observedAt)
	if err != nil || !verdict.Good {
		return nil, ErrUnsafe
	}
	return bytes.Clone(der), nil
}
