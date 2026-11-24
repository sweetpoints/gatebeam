package application

import "gatebeam-ca/internal/platform/transaction"

type RecoveryRepository interface{ QuarantineRecovery(transaction.Scope) error }

func RecoverWithin(sc transaction.Scope, r RecoveryRepository) error { return r.QuarantineRecovery(sc) }
