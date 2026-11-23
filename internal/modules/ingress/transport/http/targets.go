package http

import (
	app "gatebeam/internal/modules/ingress/application"
	"gatebeam/internal/modules/ingress/domain"
	"github.com/labstack/echo/v5"
)

func registerTargets(e *echo.Echo, s *app.Service, protect func(func(*echo.Context, app.ActorRef) error) echo.HandlerFunc) {
	e.GET("/targets/:id", protect(func(c *echo.Context, a app.ActorRef) error {
		v, err := s.Target(c.Request().Context(), a, c.Param("id"))
		if err != nil {
			return failure(c, err)
		}
		return c.JSON(200, v)
	}))
	for _, create := range []bool{true, false} {
		create := create
		path := "/targets/:id"
		method := "PUT"
		if create {
			path = "/targets"
			method = "POST"
		}
		e.Add(method, path, protect(func(c *echo.Context, a app.ActorRef) error {
			var in struct {
				Config   domain.TargetConfig `json:"config"`
				Expected int64               `json:"expected_revision"`
			}
			if err := decode(c, &in); err != nil {
				return failure(c, err)
			}
			id := c.Param("id")
			if create && in.Expected != 0 {
				return failure(c, domain.ErrInvalid)
			}
			v, err := s.Mutate(c.Request().Context(), a, app.Mutation{Kind: "target.save", ResourceID: id, Expected: in.Expected, Target: &in.Config}, c.Request().Header.Get("Idempotency-Key"))
			if err != nil {
				return failure(c, err)
			}
			status := 200
			if create {
				status = 201
			}
			return c.JSON(status, v)
		}))
	}
	for _, create := range []bool{true, false} {
		create := create
		path := "/groups/:id"
		method := "PUT"
		if create {
			path = "/groups"
			method = "POST"
		}
		e.Add(method, path, protect(func(c *echo.Context, a app.ActorRef) error {
			var in struct {
				Name     string `json:"name"`
				Expected int64  `json:"expected_revision"`
			}
			if err := decode(c, &in); err != nil {
				return failure(c, err)
			}
			if create && in.Expected != 0 {
				return failure(c, domain.ErrInvalid)
			}
			v, err := s.Mutate(c.Request().Context(), a, app.Mutation{Kind: "group.save", ResourceID: c.Param("id"), Expected: in.Expected, GroupName: in.Name}, c.Request().Header.Get("Idempotency-Key"))
			if err != nil {
				return failure(c, err)
			}
			status := 200
			if create {
				status = 201
			}
			return c.JSON(status, v)
		}))
	}
}
