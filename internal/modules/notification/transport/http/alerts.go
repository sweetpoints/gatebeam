// Package http exposes metadata and asynchronous safe channel tests.
package http

import (
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/notification/application"
	"gatebeam/internal/modules/notification/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
)

type Factory func(*echo.Context, string, bool) (*app.Management, app.ActorRef, error)

func fail(c *echo.Context, err error) error {
	status, code := 503, "unavailable"
	if errors.Is(err, domain.ErrDenied) || errors.Is(err, domain.ErrNotFound) {
		status, code = 403, "forbidden"
	}
	if errors.Is(err, domain.ErrInvalid) {
		status, code = 400, "invalid_request"
	}
	if errors.Is(err, domain.ErrConflict) {
		status, code = 409, "revision_conflict"
	}
	return c.JSON(status, map[string]string{"code": code})
}
func decode(c *echo.Context, out any) error {
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16384))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(out) != nil || d.Decode(&extra) != io.EOF {
		return domain.ErrInvalid
	}
	return nil
}
func Register(e *echo.Echo, factory Factory) {
	e.GET("/alerts", func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		m, a, err := factory(c, "", false)
		if err != nil {
			return fail(c, err)
		}
		out, err := m.Activity(c.Request().Context(), a)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(200, out)
	})
	e.GET("/alert-channels", func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		m, a, err := factory(c, "", false)
		if err != nil {
			return fail(c, err)
		}
		out, err := m.List(c.Request().Context(), a)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(200, out)
	})
	e.PUT("/alert-channels", func(c *echo.Context) error {
		var input struct {
			Channel  app.Channel `json:"channel"`
			Expected int64       `json:"expected_revision"`
			Secret   string      `json:"secret"`
			Code     string      `json:"totp"`
		}
		if err := decode(c, &input); err != nil {
			return fail(c, err)
		}
		if input.Channel.OwnerID != "" || input.Channel.Revision != 0 {
			return fail(c, domain.ErrInvalid)
		}
		m, a, err := factory(c, input.Code, true)
		if err != nil {
			return fail(c, err)
		}
		secret := []byte(input.Secret)
		defer clear(secret)
		out, err := m.Save(c.Request().Context(), a, input.Channel, input.Expected, secret)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(200, out)
	})
	e.POST("/alert-channels/:id/test", func(c *echo.Context) error {
		var input struct {
			Code string `json:"totp"`
		}
		if err := decode(c, &input); err != nil {
			return fail(c, err)
		}
		m, a, err := factory(c, input.Code, true)
		if err != nil {
			return fail(c, err)
		}
		if err = m.Test(c.Request().Context(), a, c.Param("id")); err != nil {
			return fail(c, err)
		}
		return c.JSON(202, map[string]string{"status": "queued"})
	})
}
