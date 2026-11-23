// Package http exposes material management, never issuance or network probes.
package http

import (
	"bytes"
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/certificates/application"
	"gatebeam/internal/modules/certificates/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
)

type QueryFactory func(*echo.Context) (*app.Queries, app.ActorRef, error)
type WriteFactory func(*echo.Context, string) (*app.Management, *app.Service, app.ActorRef, error)

func failure(c *echo.Context, e error) error {
	status, code := 503, "unavailable"
	switch {
	case errors.Is(e, domain.ErrDenied), errors.Is(e, domain.ErrNotFound):
		status, code = 403, "forbidden"
	case errors.Is(e, domain.ErrInvalid):
		status, code = 400, "invalid_request"
	case errors.Is(e, domain.ErrConflict):
		status, code = 409, "revision_conflict"
	case errors.Is(e, domain.ErrUnavailable):
		status, code = 409, "materials_unavailable"
	}
	return c.JSON(status, map[string]string{"code": code})
}
func decode(c *echo.Context, v any) error {
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 1048576))
	d.DisallowUnknownFields()
	var extra any
	if d.Decode(v) != nil || d.Decode(&extra) != io.EOF {
		return domain.ErrInvalid
	}
	return nil
}
func config(b json.RawMessage, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		return domain.ErrInvalid
	}
	return nil
}
func validKind(k string) bool {
	return k == "spec" || k == "account" || k == "credential" || k == "trust"
}
func Register(e *echo.Echo, queries QueryFactory, writes WriteFactory) {
	e.GET("/certificates/:kind", func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		q, a, err := queries(c)
		if err != nil {
			return failure(c, err)
		}
		out, err := q.List(c.Request().Context(), a, c.Param("kind"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, map[string]any{"items": out})
	})
	e.GET("/certificates/:kind/:id", func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		q, a, err := queries(c)
		if err != nil {
			return failure(c, err)
		}
		out, err := q.Read(c.Request().Context(), a, c.Param("kind"), c.Param("id"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, out)
	})
	save := func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")
		var in struct {
			Expected int64           `json:"expected_revision"`
			Config   json.RawMessage `json:"config"`
			Secret   string          `json:"secret"`
			PEM      string          `json:"pem"`
			Code     string          `json:"totp_code"`
		}
		if err := decode(c, &in); err != nil {
			return failure(c, err)
		}
		m, _, a, err := writes(c, in.Code)
		if err != nil {
			return failure(c, err)
		}
		var out app.Resource
		id := c.Param("id")
		if (c.Request().Method == "POST" && in.Expected != 0) || (c.Request().Method == "PUT" && (id == "" || in.Expected < 1)) {
			return failure(c, domain.ErrInvalid)
		}
		switch c.Param("kind") {
		case "spec":
			var v app.Spec
			err = config(in.Config, &v)
			if err == nil {
				out, err = m.SaveSpec(c.Request().Context(), a, id, in.Expected, v)
			}
		case "account":
			var v app.ProviderAccount
			err = config(in.Config, &v)
			if err == nil {
				out, err = m.SaveAccount(c.Request().Context(), a, id, in.Expected, v, []byte(in.Secret))
			}
		case "credential":
			var v app.DNSCredential
			err = config(in.Config, &v)
			if err == nil {
				out, err = m.SaveCredential(c.Request().Context(), a, id, in.Expected, v, []byte(in.Secret))
			}
		case "trust":
			var v app.TrustBundle
			err = config(in.Config, &v)
			if err == nil {
				out, err = m.SaveTrust(c.Request().Context(), a, id, in.Expected, v, []byte(in.PEM))
			}
		default:
			err = domain.ErrInvalid
		}
		in.Secret = ""
		in.Code = ""
		if err != nil {
			return failure(c, err)
		}
		status := 200
		if id == "" {
			status = 201
		}
		return c.JSON(status, out)
	}
	e.POST("/certificates/:kind", save)
	e.PUT("/certificates/:kind/:id", save)
	e.POST("/certificates/:kind/:id/enabled", func(c *echo.Context) error {
		var in struct {
			Revision int64  `json:"expected_revision"`
			Enabled  *bool  `json:"enabled"`
			Code     string `json:"totp_code"`
		}
		if decode(c, &in) != nil || in.Enabled == nil || in.Revision < 1 || !validKind(c.Param("kind")) {
			return failure(c, domain.ErrInvalid)
		}
		m, _, a, err := writes(c, in.Code)
		if err != nil {
			return failure(c, err)
		}
		err = m.SetEnabled(c.Request().Context(), a, c.Param("kind"), c.Param("id"), in.Revision, *in.Enabled)
		if err != nil {
			return failure(c, err)
		}
		return c.NoContent(204)
	})
	e.POST("/certificates/spec/:id/import", func(c *echo.Context) error {
		var in struct {
			Certificate string `json:"certificate_pem"`
			Key         string `json:"private_key_pem"`
			Code        string `json:"totp_code"`
		}
		if decode(c, &in) != nil {
			return failure(c, domain.ErrInvalid)
		}
		_, s, a, err := writes(c, in.Code)
		if err != nil {
			return failure(c, err)
		}
		key := []byte(in.Key)
		defer clear(key)
		out, err := s.Import(c.Request().Context(), a, c.Param("id"), []byte(in.Certificate), key)
		in.Key = ""
		if err != nil {
			return failure(c, err)
		}
		out.PrivateMaterialRef = ""
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.JSON(201, out)
	})
}
