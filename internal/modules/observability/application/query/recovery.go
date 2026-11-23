package query

import "gatebeam/internal/platform/transaction"

// Recovery invalidates ephemeral query execution authority while retaining log
// provenance and archive catalogs. A restore is never an executor lease renewal.
type Recovery interface{ QuarantineQueriesWithin(transaction.Scope) error }

func RecoverWithin(sc transaction.Scope, r Recovery) error { return r.QuarantineQueriesWithin(sc) }
