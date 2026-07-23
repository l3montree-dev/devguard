package middlewares

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho"
	"go.opentelemetry.io/otel/trace"
)

func registerMiddlewares(e *echo.Echo) {

	if os.Getenv("PROFILE") == "true" {
		if password := os.Getenv("PPROF_PASSWORD"); password != "" {
			slog.Info("enabling pprof endpoints under /debug/pprof (basic auth enabled)", "pprofPassword", password)
		} else {
			slog.Warn("enabling pprof endpoints under /debug/pprof (no authentication)")
		}
		AddProfileEndpoints(e)
	}

	// otelecho creates OTel HTTP spans; sentryotel bridges these to GlitchTip/Sentry transactions.
	// This lets DB spans (from gorm.io/plugin/opentelemetry) nest under the HTTP span.
	e.Use(otelecho.Middleware("devguard"))

	// Expose the trace ID to clients so they can correlate frontend errors / support requests.
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)
			if spanCtx := trace.SpanFromContext(c.Request().Context()).SpanContext(); spanCtx.IsValid() {
				c.Response().Header().Set("X-Trace-ID", spanCtx.TraceID().String())
			}
			return err
		}
	})

	// Expose the trace ID to the client so it can be referenced in Jaeger / GlitchTip.
	e.Use(traceID())

	// AddTrailingSlash normalises REST endpoints, but it must be skipped for
	// the OCI Distribution Spec routes — /v2/<name>/manifests/<reference> and
	// friends are defined without trailing slashes, and adding one causes
	// every registry (ghcr.io, quay.io, ...) to return 404.
	e.Pre(middleware.AddTrailingSlashWithConfig(middleware.TrailingSlashConfig{
		Skipper: func(c echo.Context) bool {
			return strings.HasPrefix(c.Request().URL.Path, "/v2/")
		},
	}))
	e.Use(middleware.CORSWithConfig(
		middleware.CORSConfig{
			AllowOrigins:     []string{"http://localhost:3000"},
			AllowHeaders:     middleware.DefaultCORSConfig.AllowHeaders,
			AllowMethods:     middleware.DefaultCORSConfig.AllowMethods,
			AllowCredentials: true,
			ExposeHeaders:    []string{"X-Trace-ID"},
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
	// Use a background request so that Request().Context() works in goroutines
	bgReq, _ := http.NewRequest("GET", "/", nil) // nosemgrep: http-new-request-without-context -- intentional background context: this synthetic request is only used to satisfy echo's Context interface in goroutines, it is never dispatched over the network
	ctx := E.NewContext(bgReq, httptest.NewRecorder())

	// copy all request-scoped values that might be needed in goroutines
	shared.CopyContextValues(c, ctx)

	return ctx
}
