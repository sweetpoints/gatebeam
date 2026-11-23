package httptransport

import (
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/pki/application"
	acmeapp "gatebeam/internal/modules/pki/application/acme"
	"gatebeam/internal/modules/pki/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
)

// GrantFactory authenticates the real request and binds its fresh MFA proof in
// integration; it returns no signer and never accepts an actor from JSON.
type GrantFactory func(*echo.Context, string) (*application.GrantService, application.ActorRef, error)

func RegisterGrants(e *echo.Echo, factory GrantFactory) {
	fail := func(c *echo.Context, err error) error {
		status := 503
		if errors.Is(err, application.ErrGrantDenied) {
			status = 403
		}
		if errors.Is(err, domain.ErrPolicy) {
			status = 400
		}
		if errors.Is(err, acmeapp.ErrNotFound) {
			status = 404
		}
		return c.JSON(status, map[string]string{"error": "PKI request rejected"})
	}
	decode := func(c *echo.Context, v any) error {
		d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 16384))
		d.DisallowUnknownFields()
		if e := d.Decode(v); e != nil {
			return e
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return errors.New("invalid request")
		}
		return nil
	}
	e.POST("/pki/grants", func(c *echo.Context) error {
		var in struct {
			application.GrantSpec
			Code string `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid request"})
		}
		service, actor, err := factory(c, in.Code)
		if err != nil {
			return fail(c, err)
		}
		result, err := service.Authorize(c.Request().Context(), actor, in.GrantSpec)
		if err != nil {
			return fail(c, err)
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(201, result)
	})
	e.POST("/pki/grants/:id/eab", func(c *echo.Context) error {
		var in struct {
			Code string `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid request"})
		}
		service, actor, err := factory(c, in.Code)
		if err != nil {
			return fail(c, err)
		}
		result, err := service.IssueEAB(c.Request().Context(), actor, c.Param("id"))
		if err != nil {
			return fail(c, err)
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(201, result)
	})
	e.POST("/pki/principals/:id/disable", func(c *echo.Context) error {
		var in struct {
			Code string `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return c.JSON(400, map[string]string{"error": "invalid request"})
		}
		service, actor, err := factory(c, in.Code)
		if err != nil {
			return fail(c, err)
		}
		if err = service.DisablePrincipal(c.Request().Context(), actor, c.Param("id")); err != nil {
			return fail(c, err)
		}
		return c.NoContent(204)
	})
}
