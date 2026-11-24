// Package transaction defines application-facing atomic work without driver types.
package transaction

import "context"

type Scope interface{ Context() context.Context }
type Runner interface {
	Within(context.Context, func(Scope) error) error
}
