package composition

import (
	"context"
	"errors"
	logdomain "gatebeam/internal/modules/observability/domain"
	"gatebeam/internal/modules/observability/infrastructure/queryipc"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
)

func TestQueryCapabilityFailureKeepsOnlyFixedClasses(t *testing.T) {
	const private = "owned-private-query-path-and-credentials"
	for _, row := range []struct {
		err   error
		class string
	}{
		{errors.Join(errors.New(private), context.DeadlineExceeded), "deadline"},
		{context.Canceled, "cancelled"},
		{logdomain.ErrQueryTimeout, "timeout"},
		{logdomain.ErrQueryBusy, "busy"},
		{pgx.ErrNoRows, "missing-object"},
		{logdomain.ErrIncomplete, "incomplete"},
		{logdomain.ErrInvalid, "invalid"},
		{logdomain.ErrCapacity, "capacity"},
		{queryipc.ErrUnavailable, "unavailable"},
		{errors.New(private), "failed"},
	} {
		class := queryCapabilityFailureClass(row.err)
		if class != row.class || strings.Contains(class, private) {
			t.Fatal("query failure lost its fixed class or disclosed the original error")
		}
	}
}
