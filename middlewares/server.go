package middlewares

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func registerMiddlewares(e *echo.Echo) {
	e.Pre(middleware.AddTrailingSlash())
	e.Use(middleware.CORSWithConfig(
		middleware.CORSConfig{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowHeaders:     middleware.DefaultCORSConfig.AllowHeaders,
			AllowMethods:     middleware.DefaultCORSConfig.AllowMethods,
			AllowCredentials: true,
		},
	))

	e.Use(logger())

	e.Use(recovermiddleware())

	e.HTTPErrorHandler = func(err error, ctx echo.Context) {
		// do the logging straight inside the error handler
		// this keeps controller methods clean
		slog.Error(err.Error(), "method", ctx.Request().Method, "path", ctx.Request().URL)

		if ctx.Response().Committed {
			return
		}

		if he, ok := err.(*echo.HTTPError); ok {
			// Send response
			if err := ctx.JSON(he.Code, he.Message); err != nil {
				slog.Error("could not send error response", "error", err)
			}
			return
		}

		he := &echo.HTTPError{
			Code:    http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
		}

		code := he.Code
		message := he.Message

		switch m := he.Message.(type) {
		case string:
			if e.Debug {
				message = echo.Map{"message": m, "error": err.Error()}
			} else {
				message = echo.Map{"message": m}
			}
		case json.Marshaler:
			// do nothing - this type knows how to format itself to JSON
		case error:
			message = echo.Map{"message": m.Error()}
		}

		// Send response
		if ctx.Request().Method == http.MethodHead { // Issue #608
			if err := ctx.NoContent(he.Code); err != nil {
				slog.Error("could not send error response", "error", err)
			}
		} else {
			if err := ctx.JSON(code, message); err != nil {
				slog.Error("could not send error response", "error", err)
			}
		}
	}
}

var E *echo.Echo

func Server() *echo.Echo {
	E = echo.New()
	E.HideBanner = true
	E.Logger.SetLevel(99)
	registerMiddlewares(E)
	return E
}

func GoroutineSafeContext(c shared.Context) shared.Context {
	// create a new context - with only the values
	ctx := E.NewContext(nil, httptest.NewRecorder())

	// copy all values from the original context that might be needed in goroutines
	if thirdParty, ok := c.Get("thirdPartyIntegration").(shared.IntegrationAggregate); ok {
		ctx.Set("thirdPartyIntegration", thirdParty)
	}

	if session, ok := c.Get("session").(shared.AuthSession); ok {
		ctx.Set("session", session)
	}

	if org, ok := c.Get("organization").(models.Org); ok {
		ctx.Set("organization", org)
	}

	if project, ok := c.Get("project").(models.Project); ok {
		ctx.Set("project", project)
	}

	if asset, ok := c.Get("asset").(models.Asset); ok {
		ctx.Set("asset", asset)
	}

	if assetVersion, ok := c.Get("assetVersion").(models.AssetVersion); ok {
		ctx.Set("assetVersion", assetVersion)
	}

	if rbac, ok := c.Get("rbac").(shared.AccessControl); ok {
		ctx.Set("rbac", rbac)
	}

	if authClient, ok := c.Get("authAdminClient").(shared.AdminClient); ok {
		ctx.Set("authAdminClient", authClient)
	}

	// Copy string values that might be needed
	if orgSlug, ok := c.Get("orgSlug").(string); ok {
		ctx.Set("orgSlug", orgSlug)
	}

	if projectSlug, ok := c.Get("projectSlug").(string); ok {
		ctx.Set("projectSlug", projectSlug)
	}

	if assetSlug, ok := c.Get("assetSlug").(string); ok {
		ctx.Set("assetSlug", assetSlug)
	}

	// Copy public request flag
	if c.Get("publicRequest") != nil {
		ctx.Set("publicRequest", true)
	}

	return ctx
}
