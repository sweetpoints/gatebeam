package http

import (
	"context"
	"errors"
	"gatebeam/internal/integration/migration"
	"gatebeam/internal/modules/deployment/application/preflight"
	"github.com/labstack/echo/v5"
)

type Migration interface {
	Check(context.Context, migration.ActorRef, string, preflight.EntryAddress) (preflight.Report, error)
}

func RegisterPreflight(e *echo.Echo, s Migration, auth Authenticate) {
	e.POST("/sites/:id/preflight", func(c *echo.Context) error {
		a, err := auth(c, true)
		if err != nil {
			return reply(c, 401, "unauthenticated")
		}
		var in preflight.EntryAddress
		if err = decode(c, &in); err != nil {
			return failure(c, err)
		}
		out, err := s.Check(c.Request().Context(), migration.ActorRef{UserID: a.UserID, AuthVersion: a.AuthVersion, CredentialKind: a.CredentialKind, CredentialID: a.CredentialID}, c.Param("id"), in)
		if errors.Is(err, migration.ErrDenied) {
			return reply(c, 403, "forbidden")
		}
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, out)
	})
}
