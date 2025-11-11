package tests

import (
	"net/http"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

func NewContext(r *http.Request, w http.ResponseWriter) shared.Context {
	app := echo.New()
	return app.NewContext(r, w)
}
