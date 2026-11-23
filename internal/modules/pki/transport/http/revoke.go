package httptransport

import (
	"encoding/json"
	"errors"
	management "gatebeam/internal/modules/pki/application"
	acmeapp "gatebeam/internal/modules/pki/application/acme"
	"gatebeam/internal/modules/pki/application/status"
	"gatebeam/internal/modules/pki/domain"
	"github.com/labstack/echo/v5"
	"io"
	"net/http"
)

type RevocationFactory func(*echo.Context, string) (*status.Management, management.ActorRef, error)

func RegisterRevocations(e *echo.Echo, factory RevocationFactory) {
	e.POST("/pki/issuers/:issuer/certificates/:serial/revoke", func(c *echo.Context) error {
		var in struct {
			Code   string `json:"totp_code"`
			Reason int    `json:"reason"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(c.Response(), c.Request().Body, 4096))
		decoder.DisallowUnknownFields()
		var extra any
		if decoder.Decode(&in) != nil || decoder.Decode(&extra) != io.EOF {
			return c.JSON(400, map[string]string{"error": "invalid request"})
		}
		service, actor, err := factory(c, in.Code)
		if err == nil {
			err = service.Revoke(c.Request().Context(), actor, c.Param("issuer"), c.Param("serial"), in.Reason)
		}
		if err != nil {
			code := 503
			switch {
			case errors.Is(err, management.ErrGrantDenied), errors.Is(err, status.ErrDenied):
				code = 403
			case errors.Is(err, domain.ErrRevocationReason), errors.Is(err, domain.ErrPolicy):
				code = 400
			case errors.Is(err, acmeapp.ErrNotFound):
				code = 404
			case errors.Is(err, domain.ErrAlreadyRevoked):
				code = 409
			}
			return c.JSON(code, map[string]string{"error": "PKI revocation rejected"})
		}
		c.Response().Header().Set("Cache-Control", "no-store")
		return c.NoContent(204)
	})
}
