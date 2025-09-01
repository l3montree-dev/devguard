package echohttp

import (
	"encoding/json"
	"log/slog"
	"net/http"

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
