// Package http exposes authorized release metadata; internal snapshots never cross REST.
package http

import (
	"context"
	"encoding/json"
	"errors"
	"gatebeam/internal/integration/publication"
	"gatebeam/internal/modules/deployment/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
	"strconv"
)

type Service interface {
	PrepareHistorical(context.Context, publication.ActorRef, string, []string, map[string]int64) (publication.CandidateView, error)
	Prepare(context.Context, publication.ActorRef, []string, map[string]int64) (publication.CandidateView, error)
	Publish(context.Context, publication.ActorRef, string) (string, error)
	Version(context.Context, publication.ActorRef, string) (publication.CandidateView, error)
	Versions(context.Context, publication.ActorRef, int, int) (publication.VersionsPage, error)
}
type Authenticate func(*echo.Context, bool) (publication.ActorRef, error)

func reply(c *echo.Context, status int, code string) error {
	return c.JSON(status, map[string]string{"code": code, "message": code, "request_id": c.Response().Header().Get("X-Request-ID")})
}
func failure(c *echo.Context, e error) error {
	switch {
	case errors.Is(e, publication.ErrDenied):
		return reply(c, 403, "forbidden")
	case errors.Is(e, domain.ErrInvalid):
		return reply(c, 400, "invalid_request")
	case errors.Is(e, domain.ErrConflict):
		return reply(c, 409, "revision_conflict")
	case errors.Is(e, domain.ErrUnavailable):
		return reply(c, 409, "materials_unavailable")
	default:
		return reply(c, 503, "unavailable")
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
func Register(e *echo.Echo, s Service, auth Authenticate) {
	protect := func(fn func(*echo.Context, publication.ActorRef) error) echo.HandlerFunc {
		return func(c *echo.Context) error {
			a, err := auth(c, c.Request().Method != "GET")
			if err != nil {
				return reply(c, 401, "unauthenticated")
			}
			return fn(c, a)
		}
	}

	e.POST("/releases/:id/prepare-historical", protect(func(c *echo.Context, a publication.ActorRef) error {
		var in struct {
			SiteIDs  []string         `json:"site_ids"`
			Expected map[string]int64 `json:"expected"`
		}
		if err := decode(c, &in); err != nil {
			return failure(c, err)
		}
		out, err := s.PrepareHistorical(c.Request().Context(), a, c.Param("id"), in.SiteIDs, in.Expected)
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(201, out)
	}))
	e.POST("/releases/prepare", protect(func(c *echo.Context, a publication.ActorRef) error {
		var in struct {
			SiteIDs  []string         `json:"site_ids"`
			Expected map[string]int64 `json:"expected"`
		}
		if err := decode(c, &in); err != nil {
			return failure(c, err)
		}
		out, err := s.Prepare(c.Request().Context(), a, in.SiteIDs, in.Expected)
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(201, out)
	}))
	e.POST("/releases/:id/publish", protect(func(c *echo.Context, a publication.ActorRef) error {
		id, err := s.Publish(c.Request().Context(), a, c.Param("id"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(202, map[string]any{"id": id, "state": "queued", "effective": false})
	}))
	e.GET("/releases", protect(func(c *echo.Context, a publication.ActorRef) error {
		limit, offset := 25, 0
		for k := range c.QueryParams() {
			if k != "limit" && k != "offset" {
				return failure(c, domain.ErrInvalid)
			}
		}
		var err error
		if v := c.QueryParam("limit"); v != "" {
			limit, err = strconv.Atoi(v)
			if err != nil {
				return failure(c, domain.ErrInvalid)
			}
		}
		if v := c.QueryParam("offset"); v != "" {
			offset, err = strconv.Atoi(v)
			if err != nil {
				return failure(c, domain.ErrInvalid)
			}
		}
		out, err := s.Versions(c.Request().Context(), a, limit, offset)
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, out)
	}))
	e.GET("/releases/:id", protect(func(c *echo.Context, a publication.ActorRef) error {
		out, err := s.Version(c.Request().Context(), a, c.Param("id"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, out)
	}))
	e.GET("/releases/:id/diff", protect(func(c *echo.Context, a publication.ActorRef) error {
		out, err := s.Version(c.Request().Context(), a, c.Param("id"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, map[string]any{"id": out.ID, "input_digest": out.InputDigest, "changes": out.Changes, "affected_site_ids": out.AffectedSiteIDs})
	}))
}
