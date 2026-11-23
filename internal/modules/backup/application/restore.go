package application

import (
	"context"
	"gatebeam/internal/modules/backup/domain"
	"reflect"
	"time"
)

type RestoreReport struct {
	Manifest                 Manifest
	Mode                     RestoreMode
	source, identity, digest string
}
type Restorer struct {
	Decoder     Decoder
	Destination Destination
}

func (r *Restorer) Verify(ctx context.Context, source, identityFile string) (RestoreReport, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	a, d, e := r.Decoder.Decode(ctx, source, identityFile)
	if e != nil {
		return RestoreReport{}, e
	}
	if e = a.Manifest.Validate(); e != nil {
		return RestoreReport{}, e
	}
	return RestoreReport{a.Manifest, Conservative, source, identityFile, d}, nil
}
func (r *Restorer) Restore(ctx context.Context, report RestoreReport, mode RestoreMode) error {
	if mode.Validate() != nil || report.Mode != Conservative || report.source == "" || report.identity == "" || !domain.ValidDigest(report.digest) {
		return domain.ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	a, d, e := r.Decoder.Decode(ctx, report.source, report.identity)
	if e != nil {
		return e
	}
	if d != report.digest || !reflect.DeepEqual(a.Manifest, report.Manifest) {
		return domain.ErrInvalid
	}
	return r.Destination.Stage(ctx, a)
}
