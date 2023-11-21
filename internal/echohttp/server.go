package echohttp

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func registerMiddlewares(e *echo.Echo) {
	e.Use(middleware.CORSWithConfig(
		middleware.CORSConfig{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowHeaders:     middleware.DefaultCORSConfig.AllowHeaders,
			AllowMethods:     middleware.DefaultCORSConfig.AllowMethods,
			AllowCredentials: true,
		},
	))

	e.Use(middleware.TimeoutWithConfig(middleware.TimeoutConfig{
		Timeout: 10 * time.Second,
	}))
	e.Use(logger())

	e.Use(recovermiddleware())

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		// do the logging straight inside the error handler
		// this keeps controller methods clean
		slog.Error(err.Error())

		if c.Response().Committed {
			return
		}

		he, ok := err.(*echo.HTTPError)
		if ok {
			if he.Internal != nil {
				if herr, ok := he.Internal.(*echo.HTTPError); ok {
					he = herr
				}
			}
		} else {
			he = &echo.HTTPError{
				Code:    http.StatusInternalServerError,
				Message: http.StatusText(http.StatusInternalServerError),
			}
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
		if c.Request().Method == http.MethodHead { // Issue #608
			c.NoContent(he.Code)
		} else {
			c.JSON(code, message)
		}
	}
}

func Server() *echo.Echo {
	e := echo.New()
	e.Logger.SetLevel(99)
	registerMiddlewares(e)
	return e
}
