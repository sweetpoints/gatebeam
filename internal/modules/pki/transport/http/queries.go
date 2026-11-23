package httptransport

import (
	"errors"
	app "gatebeam/internal/modules/pki/application"
	"github.com/labstack/echo/v5"
)

type QueryFactory func(*echo.Context) (*app.Queries, app.ActorRef, error)

func RegisterQueries(e *echo.Echo, f QueryFactory) {
	e.GET("/pki/management", func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		q, a, err := f(c)
		if err != nil {
			return c.JSON(403, map[string]string{"error": "PKI query denied"})
		}
		out, err := q.Read(c.Request().Context(), a)
		if err != nil {
			status := 503
			if errors.Is(err, app.ErrGrantDenied) {
				status = 403
			}
			return c.JSON(status, map[string]string{"error": "PKI query unavailable"})
		}
		return c.JSON(200, out)
	})
}
