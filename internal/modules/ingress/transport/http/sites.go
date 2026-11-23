// Package http implements the scoped ingress REST boundary. Authentication and
// origin/CSRF policy are supplied by the composition-owned identity boundary.
package http

import (
	"encoding/json"
	"errors"
	app "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Authenticate func(*echo.Context, bool) (app.ActorRef, error)

func restError(c *echo.Context, status int, code, message string) error {
	return c.JSON(status, map[string]string{"code": code, "message": message, "request_id": c.Response().Header().Get("X-Request-ID")})
}
func failure(c *echo.Context, e error) error {
	switch {
	case errors.Is(e, app.ErrDenied), errors.Is(e, domain.ErrNotFound):
		return restError(c, 403, "forbidden", "permission denied")
	case errors.Is(e, domain.ErrInvalid):
		return restError(c, 400, "invalid_request", "invalid ingress configuration")
	case errors.Is(e, domain.ErrConflict):
		return restError(c, 409, "revision_conflict", "revision or domain conflict")
	case errors.Is(e, domain.ErrReferenced):
		return restError(c, 409, "resource_referenced", "resource is referenced")
	case errors.Is(e, domain.ErrUnavailable):
		return restError(c, 409, "materials_unavailable", "TLS materials unavailable")
	default:
		return restError(c, 503, "unavailable", "service unavailable")
	}
}
func decode(c *echo.Context, dst any) error {
	d := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 1048576))
	d.DisallowUnknownFields()
	if d.Decode(dst) != nil {
		return domain.ErrInvalid
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return domain.ErrInvalid
	}
	return nil
}
func pagination(c *echo.Context) (int, int, error) {
	l, o := 25, 0
	for k := range c.QueryParams() {
		if k != "limit" && k != "offset" {
			return 0, 0, domain.ErrInvalid
		}
	}
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
	if l < 1 || l > 100 || o < 0 || o > 100000 {
		return 0, 0, domain.ErrInvalid
	}
	return l, o, nil
}
func Register(e *echo.Echo, s *app.Service, auth Authenticate) {
	protect := func(fn func(*echo.Context, app.ActorRef) error) echo.HandlerFunc {
		return func(c *echo.Context) error {
			a, err := auth(c, c.Request().Method != "GET")
			if err != nil {
				return restError(c, 401, "unauthenticated", "authentication required")
			}
			return fn(c, a)
		}
	}
	e.GET("/ingress-capabilities", protect(func(c *echo.Context, a app.ActorRef) error {
		for key, values := range c.QueryParams() {
			if key != "group_ids" || len(values) != 1 {
				return failure(c, domain.ErrInvalid)
			}
		}
		var groups []string
		if value := c.QueryParam("group_ids"); value != "" {
			groups = strings.Split(value, ",")
		}
		out, err := s.Capabilities(c.Request().Context(), a, groups)
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, out)
	}))
	for _, resource := range []string{"sites", "groups", "targets"} {
		resource := resource
		e.GET("/"+resource, protect(func(c *echo.Context, a app.ActorRef) error {
			l, o, err := pagination(c)
			if err != nil {
				return failure(c, err)
			}
			var items any
			switch resource {
			case "sites":
				items, err = s.Sites(c.Request().Context(), a, l, o)
			case "groups":
				items, err = s.Groups(c.Request().Context(), a, l, o)
			case "targets":
				items, err = s.Targets(c.Request().Context(), a, l, o)
			}
			if err != nil {
				return failure(c, err)
			}
			return c.JSON(200, map[string]any{"items": items, "limit": l, "offset": o})
		}))
	}
	e.POST("/sites", protect(func(c *echo.Context, a app.ActorRef) error {
		var input struct {
			Name     string          `json:"name"`
			GroupIDs []string        `json:"group_ids"`
			Config   siteConfigInput `json:"config"`
		}
		if err := decode(c, &input); err != nil {
			return failure(c, err)
		}
		cfg, err := input.Config.value(false)
		if err != nil {
			return failure(c, err)
		}
		in := app.CreateSite{Name: input.Name, GroupIDs: input.GroupIDs, Config: cfg}
		v, err := s.Mutate(c.Request().Context(), a, app.Mutation{Kind: "site.create", Site: &in}, c.Request().Header.Get("Idempotency-Key"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(201, v)
	}))
	e.GET("/sites/:id", protect(func(c *echo.Context, a app.ActorRef) error {
		v, err := s.Site(c.Request().Context(), a, c.Param("id"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, v)
	}))
	e.PUT("/sites/:id/draft", protect(func(c *echo.Context, a app.ActorRef) error {
		var in struct {
			Config   siteConfigInput `json:"config"`
			Expected int64           `json:"expected_revision"`
		}
		if err := decode(c, &in); err != nil {
			return failure(c, err)
		}
		cfg, err := in.Config.value(true)
		if err != nil {
			return failure(c, err)
		}
		v, err := s.Mutate(c.Request().Context(), a, app.Mutation{Kind: "site.save", ResourceID: c.Param("id"), Expected: in.Expected, Draft: &app.Draft{SiteID: c.Param("id"), Config: cfg}}, c.Request().Header.Get("Idempotency-Key"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, v)
	}))
	e.PUT("/sites/:id/groups", protect(func(c *echo.Context, a app.ActorRef) error {
		var in struct {
			GroupIDs *[]string `json:"group_ids"`
			Expected int64     `json:"expected_revision"`
		}
		if err := decode(c, &in); err != nil {
			return failure(c, err)
		}
		if in.GroupIDs == nil {
			return failure(c, domain.ErrInvalid)
		}
		if _, err := s.Mutate(c.Request().Context(), a, app.Mutation{Kind: "site.groups", ResourceID: c.Param("id"), Expected: in.Expected, GroupIDs: *in.GroupIDs}, c.Request().Header.Get("Idempotency-Key")); err != nil {
			return failure(c, err)
		}
		return c.NoContent(204)
	}))
	for _, resource := range []string{"sites", "groups", "targets"} {
		resource := resource
		e.DELETE("/"+resource+"/:id", protect(func(c *echo.Context, a app.ActorRef) error {
			var in struct {
				Expected int64 `json:"expected_revision"`
			}
			if err := decode(c, &in); err != nil {
				return failure(c, err)
			}
			kinds := map[string]string{"sites": "site.delete", "groups": "group.delete", "targets": "target.delete"}
			_, err := s.Mutate(c.Request().Context(), a, app.Mutation{Kind: kinds[resource], ResourceID: c.Param("id"), Expected: in.Expected}, c.Request().Header.Get("Idempotency-Key"))
			if err != nil {
				return failure(c, err)
			}
			return c.NoContent(204)
		}))
	}
	registerTargets(e, s, protect)
}

// Raw enabled distinguishes omission/null from false at the full-draft boundary.
// The embedded domain config retains strict unknown-field decoding.
type siteConfigInput struct {
	domain.SiteConfig
	Enabled json.RawMessage `json:"enabled"`
}

func (v siteConfigInput) value(required bool) (domain.SiteConfig, error) {
	c := v.SiteConfig
	if len(v.Enabled) == 0 {
		if required {
			return c, domain.ErrInvalid
		}
		c.Enabled = true
		return c, nil
	}
	if string(v.Enabled) == "null" {
		return c, domain.ErrInvalid
	}
	if json.Unmarshal(v.Enabled, &c.Enabled) != nil {
		return c, domain.ErrInvalid
	}
	return c, nil
}
