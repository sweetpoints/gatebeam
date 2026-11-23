package http

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"gatebeam/internal/modules/identity/application/auth"
	"github.com/labstack/echo/v5"
	"strings"
)

func requestID() string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}
func restError(c *echo.Context, status int, code, message string) error {
	return c.JSON(status, map[string]string{"code": code, "message": message, "request_id": c.Response().Header().Get("X-Request-ID")})
}

type writeAuthenticator interface {
	AuthenticateWrite(context.Context, string, string) (auth.Actor, error)
	AuthenticateToken(context.Context, string) (auth.Actor, error)
}

func authenticateRequest(c *echo.Context, s Service, cookie string, write bool) (auth.Actor, error) {
	header := c.Request().Header.Get("Authorization")
	v, e := c.Request().Cookie(cookie)
	if header != "" {
		if e == nil && v.Value != "" {
			return auth.Actor{}, auth.ErrDenied
		}
		a, ok := s.(writeAuthenticator)
		if !ok || !strings.HasPrefix(header, "Bearer ") || strings.Contains(strings.TrimPrefix(header, "Bearer "), " ") {
			return auth.Actor{}, auth.ErrDenied
		}
		return a.AuthenticateToken(c.Request().Context(), strings.TrimPrefix(header, "Bearer "))
	}
	if e != nil {
		return auth.Actor{}, auth.ErrDenied
	}
	if write {
		a, ok := s.(writeAuthenticator)
		if !ok {
			return auth.Actor{}, auth.ErrDenied
		}
		return a.AuthenticateWrite(c.Request().Context(), v.Value, c.Request().Header.Get("X-CSRF-Token"))
	}
	return s.Authenticate(c.Request().Context(), v.Value)
}

// AuthenticateRequest preserves the same session/CSRF/Bearer rules for composed resources.
func AuthenticateRequest(c *echo.Context, s Service, cookie string, write bool) (auth.Actor, error) {
	return authenticateRequest(c, s, cookie, write)
}
