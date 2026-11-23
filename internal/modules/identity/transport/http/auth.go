// Package http implements the identity JSON boundary using Echo v5.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/modules/identity/application/auth"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Service interface {
	BeginLogin(context.Context, string, string) (auth.LoginChallenge, error)
	FinishLogin(context.Context, string, string) (auth.Session, error)
	EnrollTOTP(context.Context, string, string, string) (auth.EnrollmentResult, error)
	Recover(context.Context, string, string, string) (auth.EnrollmentChallenge, error)
	Authenticate(context.Context, string) (auth.Actor, error)
	Logout(context.Context, string, string) error
}
type Config struct {
	Origin     string
	Production bool
}

// New trusts only the configured browser origin; forwarded request headers never determine cookie security.
func New(s Service, ping func(context.Context) error, cfg Config, registrations ...func(*echo.Echo, string)) (http.Handler, error) {
	u, e := url.Parse(cfg.Origin)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || (u.Scheme != "https" && (cfg.Production || u.Scheme != "http")) {
		return nil, errors.New("invalid browser origin")
	}
	if !cfg.Production && u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return nil, errors.New("development origin must be loopback")
	}
	if s == nil || ping == nil {
		return nil, errors.New("identity dependencies required")
	}
	echos := echo.New()
	cookieName := "__Host-gatebeam"
	if !cfg.Production {
		cookieName = "gatebeam-dev"
	}
	slots := make(chan struct{}, 2)
	echos.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("X-Request-ID", requestID())
			c.Response().Header().Set("Cache-Control", "no-store")
			c.Response().Header().Set("X-Content-Type-Options", "nosniff")
			c.Response().Header().Set("Referrer-Policy", "no-referrer")
			if c.Request().Method != "GET" && c.Request().Method != "HEAD" {
				origin := c.Request().Header.Get("Origin")
				if origin != cfg.Origin && !(origin == "" && strings.HasPrefix(c.Request().Header.Get("Authorization"), "Bearer ")) {
					return restError(c, 403, "forbidden", "origin denied")
				}
				bodylessLogout := c.Request().Method == "POST" && c.Path() == "/auth/logout" && c.Request().ContentLength == 0 && len(c.Request().TransferEncoding) == 0
				if !bodylessLogout && !strings.HasPrefix(c.Request().Header.Get("Content-Type"), "application/json") {
					return restError(c, 415, "unsupported_media_type", "JSON required")
				}
				select {
				case slots <- struct{}{}:
					defer func() { <-slots }()
				default:
					return restError(c, 503, "unavailable", "service busy")
				}
			}
			ctx, cancel := context.WithTimeout(c.Request().Context(), 10*time.Second)
			defer cancel()
			c.SetRequest(c.Request().WithContext(ctx))
			return next(c)
		}
	})
	// Override default error rendering: parsing/driver errors must not disclose inputs or credentials.
	echos.HTTPErrorHandler = func(c *echo.Context, err error) {
		status := 500
		var he interface{ StatusCode() int }
		if errors.As(err, &he) && he.StatusCode() >= 400 && he.StatusCode() < 500 {
			status = he.StatusCode()
		}
		_ = restError(c, status, "request_failed", http.StatusText(status))
	}
	failure := func(c *echo.Context, err error) error {
		if errors.Is(err, auth.ErrDenied) {
			return restError(c, 401, "unauthenticated", "authentication denied")
		}
		if errors.Is(err, auth.ErrInvalid) {
			return restError(c, 400, "invalid_request", "invalid request")
		}
		return restError(c, 503, "unavailable", "authentication unavailable")
	}
	decode := func(c *echo.Context, dst any) error {
		r := http.MaxBytesReader(c.Response(), c.Request().Body, 8192)
		d := json.NewDecoder(r)
		d.DisallowUnknownFields()
		if d.Decode(dst) != nil {
			return auth.ErrInvalid
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return auth.ErrInvalid
		}
		return nil
	}
	token := func(c *echo.Context) string {
		v, e := c.Request().Cookie(cookieName)
		if e != nil {
			return ""
		}
		return v.Value
	}
	echos.GET("/livez", func(c *echo.Context) error { return c.JSON(200, map[string]string{"status": "alive"}) })
	echos.GET("/readyz", func(c *echo.Context) error {
		ctx, cancel := context.WithTimeout(c.Request().Context(), time.Second)
		defer cancel()
		if ping(ctx) != nil {
			return c.JSON(503, map[string]string{"status": "not ready"})
		}
		return c.JSON(200, map[string]string{"status": "ready"})
	})
	echos.POST("/auth/login", func(c *echo.Context) error {
		var v struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		if e := decode(c, &v); e != nil {
			return failure(c, e)
		}
		out, e := s.BeginLogin(c.Request().Context(), v.Name, v.Password)
		if e != nil {
			return failure(c, e)
		}
		return c.JSON(200, out)
	})
	echos.POST("/auth/login/finish", func(c *echo.Context) error {
		var v struct {
			Challenge string `json:"challenge_id"`
			Code      string `json:"code"`
		}
		if e := decode(c, &v); e != nil {
			return failure(c, e)
		}
		out, e := s.FinishLogin(c.Request().Context(), v.Challenge, v.Code)
		if e != nil {
			return failure(c, e)
		}
		c.SetCookie(&http.Cookie{Name: cookieName, Value: out.Token, Path: "/", Expires: out.Expires, Secure: cfg.Production, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		return c.JSON(200, out)
	})
	echos.POST("/auth/enroll", func(c *echo.Context) error {
		var v struct {
			Invite   string `json:"invite_id"`
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if e := decode(c, &v); e != nil {
			return failure(c, e)
		}
		out, e := s.EnrollTOTP(c.Request().Context(), v.Invite, v.Password, v.Code)
		if e != nil {
			return failure(c, e)
		}
		return c.JSON(200, out)
	})
	echos.POST("/auth/recover", func(c *echo.Context) error {
		var v struct {
			Name     string `json:"name"`
			Password string `json:"password"`
			Recovery string `json:"recovery_code"`
		}
		if e := decode(c, &v); e != nil {
			return failure(c, e)
		}
		out, e := s.Recover(c.Request().Context(), v.Name, v.Password, v.Recovery)
		if e != nil {
			return failure(c, e)
		}
		return c.JSON(200, out)
	})
	echos.GET("/auth/session", func(c *echo.Context) error {
		out, e := authenticateRequest(c, s, cookieName, false)
		if e != nil {
			return failure(c, e)
		}
		return c.JSON(200, out)
	})
	echos.POST("/auth/logout", func(c *echo.Context) error {
		if e := s.Logout(c.Request().Context(), token(c), c.Request().Header.Get("X-CSRF-Token")); e != nil {
			return failure(c, e)
		}
		c.SetCookie(&http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, Secure: cfg.Production, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		return c.NoContent(204)
	})
	registerManagement(echos, s, cookieName, decode)
	for _, register := range registrations {
		register(echos, cookieName)
	}
	return echos, nil
}
