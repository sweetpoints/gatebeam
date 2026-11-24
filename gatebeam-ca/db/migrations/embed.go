package migrations

import "embed"

// Files holds immutable runtime migrations.
//
//go:embed *.sql
var Files embed.FS
