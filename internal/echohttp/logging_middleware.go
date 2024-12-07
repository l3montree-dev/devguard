package echohttp

import (
	"log/slog"
	"time"

	"github.com/labstack/echo/v4"
)

// custom echo middleware used for request logging
func logger() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			now := time.Now()

			err := next(c)

			if err == nil && c.Request().URL.String() != "/api/v1/health/" {
				slog.Info("handled request", "method", c.Request().Method, "url", c.Request().URL, "status", c.Response().Status, "duration", time.Since(now))
			}
			return err
		}
	}
}
