package middleware

import (
	"log/slog"
	"time"

	"github.com/labstack/echo/v4"
)

// custom echo middleware used for request logging
func logger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) error {
			now := time.Now()

			err := next(ctx)

			if err == nil && ctx.Request().URL.String() != "/api/v1/health/" {
				slog.Info("handled request", "method", ctx.Request().Method, "url", ctx.Request().URL, "status", ctx.Response().Status, "duration", time.Since(now))
			}
			return err
		}
	}
}
