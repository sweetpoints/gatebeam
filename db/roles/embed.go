// Package roles embeds versioned runtime capability migrations.
package roles

import "embed"

// Files contains no LOGIN credentials. Only the explicit migration command uses it.
//
//go:embed *.sql
var Files embed.FS
