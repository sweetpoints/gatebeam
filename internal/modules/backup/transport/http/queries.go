package http

import (
	"errors"
	"gatebeam/internal/modules/backup/application"
	"github.com/labstack/echo/v5"
	"strconv"
)

func Register(e *echo.Echo, q *application.Queries, auth func(*echo.Context) (application.ActorRef, error)) {
	e.GET("/backups", func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		a, err := auth(c)
		if err != nil {
			return c.JSON(401, map[string]string{"code": "unauthenticated"})
		}
		l, o := 25, 0
		for k, values := range c.QueryParams() {
			if len(values) != 1 || (k != "limit" && k != "offset") {
				return c.JSON(400, map[string]string{"code": "invalid_request"})
			}
			v, e := strconv.Atoi(values[0])
			if e != nil {
				return c.JSON(400, map[string]string{"code": "invalid_request"})
			}
			if k == "limit" {
				l = v
			} else {
				o = v
			}
		}
		if l < 1 || l > 100 || o < 0 || o > 100000 {
			return c.JSON(400, map[string]string{"code": "invalid_request"})
		}
		out, err := q.List(c.Request().Context(), a, l, o)
		if err != nil {
			if errors.Is(err, application.ErrDenied) {
				return c.JSON(403, map[string]string{"code": "forbidden"})
			}
			return c.JSON(503, map[string]string{"code": "unavailable"})
		}
		return c.JSON(200, out)
	})
}
