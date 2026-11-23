package runtime

import (
	"context"
	"errors"
	"time"
)

var ErrLogCapacity = errors.New("local unarchived log capacity exceeded")

type LogUsage struct {
	Bytes, ActiveBytes int64
	Files              int
}
type LogWatermark struct {
	CheckedAt, RotatedAt time.Time
	Usage                LogUsage
	Capacity             bool
}
type LocalLogVolume interface {
	Lock(context.Context) (func(), error)
	InspectLogs(context.Context, int) (LogUsage, error)
	LogWatermark(context.Context) (LogWatermark, error)
	SaveLogWatermark(context.Context, LogWatermark) error
}
type LogRotator interface{ RotateLogs(context.Context) error }
type LocalLogPolicy struct {
	Volume                LocalLogVolume
	Process               LogRotator
	RotateBytes, MaxBytes int64
	MaxFiles              int
	MinimumInterval       time.Duration
	Now                   func() time.Time
}

// MaintainLocalLogs has no database, query engine, archive or job dependency.
// Pressure is recorded explicitly; unarchived files are never deleted here.
func MaintainLocalLogs(ctx context.Context, p LocalLogPolicy) error {
	if p.Volume == nil || p.Process == nil || p.RotateBytes < 1 || p.MaxBytes < 1 || p.MaxFiles < 1 || p.MaxFiles > 65536 {
		return errors.New("invalid local log policy")
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	if p.MinimumInterval == 0 {
		p.MinimumInterval = time.Minute
	}
	if p.MinimumInterval < 0 {
		return errors.New("invalid local log interval")
	}
	unlock, e := p.Volume.Lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	previous, e := p.Volume.LogWatermark(ctx)
	if e != nil {
		return e
	}
	now := p.Now().UTC()
	if now.Before(previous.CheckedAt) {
		return errors.New("local log clock moved backwards")
	}
	usage, e := p.Volume.InspectLogs(ctx, p.MaxFiles)
	capacity := errors.Is(e, ErrLogCapacity) || usage.Bytes >= p.MaxBytes || usage.Files >= p.MaxFiles
	if e != nil && !capacity {
		return e
	}
	current := LogWatermark{CheckedAt: now, RotatedAt: previous.RotatedAt, Usage: usage, Capacity: capacity}
	if capacity {
		if e = p.Volume.SaveLogWatermark(ctx, current); e != nil {
			return e
		}
		return ErrLogCapacity
	}
	if usage.ActiveBytes >= p.RotateBytes && (previous.RotatedAt.IsZero() || now.Sub(previous.RotatedAt) >= p.MinimumInterval) {
		if e = p.Process.RotateLogs(ctx); e != nil {
			return e
		}
		current.RotatedAt = now
	} else if previous.Usage == usage && !previous.Capacity && now.Sub(previous.CheckedAt) < p.MinimumInterval {
		return nil
	}
	return p.Volume.SaveLogWatermark(ctx, current)
}
