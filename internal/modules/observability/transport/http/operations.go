// Package http exposes fixed owner queries; no SQL, object keys or filesystem paths are accepted.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/observability/application/query"
	"gatebeam/internal/modules/observability/application/stats"
	"gatebeam/internal/modules/observability/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
	"strconv"
	"time"
)

type Authenticate func(*echo.Context, bool) (query.ActorRef, error)

func fail(c *echo.Context, e error) error {
	status, code := 503, "unavailable"
	if errors.Is(e, domain.ErrDenied) {
		status, code = 403, "forbidden"
	}
	if errors.Is(e, domain.ErrInvalid) {
		status, code = 400, "invalid_request"
	}
	if errors.Is(e, domain.ErrCapacity) {
		status, code = 413, "query_limit"
	}
	if errors.Is(e, domain.ErrIncomplete) {
		status, code = 409, "query_expired"
	}
	return c.JSON(status, map[string]string{"code": code})
}
func page(c *echo.Context) (int, int, error) {
	l, o := 25, 0
	var e error
	if v := c.QueryParam("limit"); v != "" {
		l, e = strconv.Atoi(v)
		if e != nil {
			return 0, 0, domain.ErrInvalid
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		o, e = strconv.Atoi(v)
		if e != nil {
			return 0, 0, domain.ErrInvalid
		}
	}
	return l, o, nil
}
func decode(c *echo.Context, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16384))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(v) != nil || d.Decode(&extra) != io.EOF {
		return domain.ErrInvalid
	}
	return nil
}
func Register(e *echo.Echo, s *stats.Service, q *query.Service, auth Authenticate) {
	protect := func(fn func(*echo.Context, query.ActorRef) error) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Cache-Control", "no-store")
			a, err := auth(c, c.Request().Method != "GET")
			if err != nil {
				return c.JSON(401, map[string]string{"code": "unauthenticated"})
			}
			return fn(c, a)
		}
	}
	e.POST("/statistics/query", protect(func(c *echo.Context, a query.ActorRef) error {
		var f stats.Filter
		if err := decode(c, &f); err != nil {
			return fail(c, err)
		}
		out, err := s.Query(c.Request().Context(), a, f)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(200, out)
	}))
	e.POST("/log-queries", protect(func(c *echo.Context, a query.ActorRef) error {
		var f query.Filter
		if err := decode(c, &f); err != nil {
			return fail(c, err)
		}
		out, err := q.Submit(c.Request().Context(), a, f)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(202, out)
	}))
	e.GET("/log-queries", protect(func(c *echo.Context, a query.ActorRef) error {
		l, o, err := page(c)
		if err != nil {
			return fail(c, err)
		}
		out, err := q.List(c.Request().Context(), a, l, o)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(200, map[string]any{"items": out.Items, "has_more": out.HasMore, "next_offset": out.NextOffset, "limit": l, "offset": o})
	}))
	e.GET("/log-queries/:id", protect(func(c *echo.Context, a query.ActorRef) error {
		out, err := q.Fetch(c.Request().Context(), a, c.Param("id"), c.QueryParam("cursor"))
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(200, out)
	}))
	e.POST("/log-queries/:id/cancel", protect(func(c *echo.Context, a query.ActorRef) error {
		if err := q.Cancel(c.Request().Context(), a, c.Param("id")); err != nil {
			return fail(c, err)
		}
		return c.NoContent(204)
	}))
	e.GET("/log-queries/:id/download", protect(func(c *echo.Context, a query.ActorRef) error {
		// Recheck identity/current site on every page before writing any response bytes.
		ctx, cancel := context.WithTimeout(c.Request().Context(), 5*time.Second)
		defer cancel()
		var rows []domain.QueryRow
		cursor := ""
		for i := 0; i < 100; i++ {
			out, err := q.Fetch(ctx, a, c.Param("id"), cursor)
			if err != nil {
				return fail(c, err)
			}
			if out.Job.State != "succeeded" {
				return fail(c, domain.ErrIncomplete)
			}
			rows = append(rows, out.Rows...)
			cursor = out.Cursor
			if cursor == "" {
				break
			}
		}
		c.Response().Header().Set("Content-Disposition", `attachment; filename="gatebeam-logs.json"`)
		return c.JSON(200, rows)
	}))
}
