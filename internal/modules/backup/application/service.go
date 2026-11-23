package application

import (
	"context"
	"gatebeam/internal/modules/backup/domain"
	"time"
)

type Service struct {
	Source  Source
	Objects Objects
	Catalog Catalog
	Now     func() time.Time
}

func (s *Service) Create(ctx context.Context, p Policy) (Manifest, error) {
	if e := p.Validate(); e != nil {
		return Manifest{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	a, e := s.Source.Latest(ctx, p.MaxAge)
	if e != nil {
		return Manifest{}, e
	}
	if e = a.Manifest.Validate(); e != nil {
		return Manifest{}, e
	}
	if !domain.ValidDigest(a.SHA256) || a.Bytes <= 0 || a.Bytes > domain.MaxArchive {
		return Manifest{}, domain.ErrInvalid
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if a.Manifest.Created.After(now.Add(time.Minute)) || now.Sub(a.Manifest.Created) > p.MaxAge {
		return Manifest{}, domain.ErrInvalid
	}
	if e = s.Objects.PutVerified(ctx, a); e != nil {
		return Manifest{}, e
	}
	if e = s.Catalog.Confirm(ctx, a); e != nil {
		return Manifest{}, e
	}
	old, e := s.Catalog.Expired(ctx, now.Add(-p.Retain), a.Manifest.ID)
	if e != nil {
		return Manifest{}, e
	}
	for _, id := range old {
		if !domain.ValidDigest(id) {
			return Manifest{}, domain.ErrInvalid
		}
		if e = s.Objects.Delete(ctx, id); e != nil {
			return Manifest{}, e
		}
		if e = s.Source.Cleanup(ctx, id); e != nil {
			return Manifest{}, e
		}
		if e = s.Catalog.Forget(ctx, id); e != nil {
			return Manifest{}, e
		}
	}
	return a.Manifest, nil
}
