package recovery

import "gatebeam/internal/platform/transaction"

type Repository interface{ QuarantineRecovery(transaction.Scope) error }

func Within(sc transaction.Scope, r Repository) error { return r.QuarantineRecovery(sc) }
