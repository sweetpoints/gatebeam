package application

import (
	"context"
	"gatebeam/internal/modules/backup/domain"
	"time"
)

type Policy = domain.Policy
type Manifest = domain.Manifest
type RestoreMode = domain.RestoreMode

const Conservative = domain.Conservative

type Artifact struct {
	Manifest Manifest
	Path     string
	SHA256   string
	Bytes    int64
}
type Source interface {
	Latest(context.Context, time.Duration) (Artifact, error)
	Cleanup(context.Context, string) error
}
type Objects interface {
	PutVerified(context.Context, Artifact) error
	Delete(context.Context, string) error
}
type Catalog interface {
	Confirm(context.Context, Artifact) error
	Expired(context.Context, time.Time, string) ([]string, error)
	Forget(context.Context, string) error
}
type Archive struct {
	Manifest Manifest
	Files    map[string][]byte
}
type Decoder interface {
	Decode(context.Context, string, string) (Archive, string, error)
}
type Destination interface {
	Stage(context.Context, Archive) error
}
