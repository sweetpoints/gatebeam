package http

import (
	"context"
	"errors"
	app "gatebeam/internal/modules/identity/application"
	"gatebeam/internal/modules/identity/application/access"
	"gatebeam/internal/modules/identity/application/auth"
	"gatebeam/internal/modules/identity/domain"
	"github.com/labstack/echo/v5"
	"strconv"
	"time"
)

type management interface {
	CreateAccount(context.Context, auth.Actor, string, string, app.Role) (auth.EnrollmentChallenge, error)
	ResetAccount(context.Context, auth.Actor, string, string) (auth.EnrollmentChallenge, error)
	DisableAccount(context.Context, auth.Actor, string, string) error
	SetAuthority(context.Context, auth.Actor, string, string, app.Role, []domain.Grant) error
	IssueToken(context.Context, auth.Actor, string, []string, []string, time.Time) (auth.IssuedToken, error)
	RevokeToken(context.Context, auth.Actor, string, string) error
	Accounts(context.Context, auth.Actor, int32, int32) ([]access.AccountView, error)
	Tokens(context.Context, auth.Actor, int32, int32) ([]access.TokenView, error)
	Audit(context.Context, auth.Actor, int32, int32) ([]access.AuditView, error)
}

func registerManagement(e *echo.Echo, s Service, cookie string, decode func(*echo.Context, any) error) {
	m, ok := s.(management)
	if !ok {
		return
	}
	fail := func(c *echo.Context, err error) error {
		if errors.Is(err, auth.ErrDenied) || errors.Is(err, auth.ErrNotFound) {
			return restError(c, 403, "forbidden", "permission denied")
		}
		if errors.Is(err, auth.ErrInvalid) || errors.Is(err, access.ErrInvalid) {
			return restError(c, 400, "invalid_request", "invalid request")
		}
		return restError(c, 503, "unavailable", "service unavailable")
	}
	protect := func(fn func(*echo.Context, auth.Actor) error) echo.HandlerFunc {
		return func(c *echo.Context) error {
			a, err := authenticateRequest(c, s, cookie, c.Request().Method != "GET")
			if err != nil {
				return restError(c, 401, "unauthenticated", "authentication required")
			}
			return fn(c, a)
		}
	}
	for _, route := range []string{"/accounts", "/tokens", "/audit"} {
		path := route
		e.GET(path, protect(func(c *echo.Context, a auth.Actor) error {
			l, o := int64(25), int64(0)
			var err error
			if v := c.QueryParam("limit"); v != "" {
				l, err = strconv.ParseInt(v, 10, 32)
				if err != nil {
					return fail(c, access.ErrInvalid)
				}
			}
			if v := c.QueryParam("offset"); v != "" {
				o, err = strconv.ParseInt(v, 10, 32)
				if err != nil {
					return fail(c, access.ErrInvalid)
				}
			}
			var items any
			switch path {
			case "/accounts":
				items, err = m.Accounts(c.Request().Context(), a, int32(l), int32(o))
			case "/tokens":
				items, err = m.Tokens(c.Request().Context(), a, int32(l), int32(o))
			case "/audit":
				items, err = m.Audit(c.Request().Context(), a, int32(l), int32(o))
			}
			if err != nil {
				return fail(c, err)
			}
			return c.JSON(200, map[string]any{"items": items, "limit": l, "offset": o, "request_id": c.Response().Header().Get("X-Request-ID")})
		}))
	}
	e.POST("/accounts", protect(func(c *echo.Context, a auth.Actor) error {
		var in struct {
			Name string   `json:"name"`
			Role app.Role `json:"role"`
			Code string   `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return fail(c, err)
		}
		v, err := m.CreateAccount(c.Request().Context(), a, in.Code, in.Name, in.Role)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(201, v)
	}))
	e.PUT("/accounts/:id/authority", protect(func(c *echo.Context, a auth.Actor) error {
		var in struct {
			Role   app.Role       `json:"role"`
			Grants []domain.Grant `json:"grants"`
			Code   string         `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return fail(c, err)
		}
		if in.Grants == nil {
			return fail(c, auth.ErrInvalid)
		}
		if err := m.SetAuthority(c.Request().Context(), a, in.Code, c.Param("id"), in.Role, in.Grants); err != nil {
			return fail(c, err)
		}
		return c.NoContent(204)
	}))
	for _, action := range []string{"reset", "disable"} {
		action := action
		e.POST("/accounts/:id/"+action, protect(func(c *echo.Context, a auth.Actor) error {
			var in struct {
				Code string `json:"totp_code"`
			}
			if err := decode(c, &in); err != nil {
				return fail(c, err)
			}
			if action == "reset" {
				v, err := m.ResetAccount(c.Request().Context(), a, in.Code, c.Param("id"))
				if err != nil {
					return fail(c, err)
				}
				return c.JSON(200, v)
			}
			if err := m.DisableAccount(c.Request().Context(), a, in.Code, c.Param("id")); err != nil {
				return fail(c, err)
			}
			return c.NoContent(204)
		}))
	}
	e.POST("/tokens", protect(func(c *echo.Context, a auth.Actor) error {
		var in struct {
			Code    string    `json:"totp_code"`
			Actions []string  `json:"actions"`
			SiteIDs []string  `json:"site_ids"`
			Expires time.Time `json:"expires"`
		}
		if err := decode(c, &in); err != nil {
			return fail(c, err)
		}
		v, err := m.IssueToken(c.Request().Context(), a, in.Code, in.Actions, in.SiteIDs, in.Expires)
		if err != nil {
			return fail(c, err)
		}
		return c.JSON(201, v)
	}))
	e.POST("/tokens/:id/revoke", protect(func(c *echo.Context, a auth.Actor) error {
		var in struct {
			Code string `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return fail(c, err)
		}
		if err := m.RevokeToken(c.Request().Context(), a, in.Code, c.Param("id")); err != nil {
			return fail(c, err)
		}
		return c.NoContent(204)
	}))
}
