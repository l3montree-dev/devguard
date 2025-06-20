package integration_tests

import (
	"net/http"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/labstack/echo/v4"
)

func NewContext(r *http.Request, w http.ResponseWriter) core.Context {
	app := echo.New()
	return app.NewContext(r, w)
}
