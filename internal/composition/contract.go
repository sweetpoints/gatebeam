package composition

import "gatebeam/internal/modules/deployment/domain"

func RuntimeContract() domain.RuntimeContract { return domain.CurrentRuntimeContract() }
