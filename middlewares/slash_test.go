package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestAddTrailingSlash(t *testing.T) {
	newServer := func() *echo.Echo {
		e := echo.New()
		e.Pre(addTrailingSlash)
		e.GET("/organizations/:organization/", func(c echo.Context) error {
			return c.String(http.StatusOK, "org")
		})
		e.GET("/v2/:image/manifests/:reference", func(c echo.Context) error {
			return c.String(http.StatusOK, "oci")
		})
		return e
	}

	serve := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		newServer().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
		return rec
	}

	t.Run("it should route a path without a trailing slash to the trailing slash route", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve("/organizations/%40opencode").Code)
	})

	// Regression: echo.GetPath - what the router matches on - prefers URL.RawPath
	// whenever it is set, which net/url does for every path carrying a %xx escape.
	// echo's own middleware.AddTrailingSlash only appends to URL.Path, so the
	// slash stayed invisible to the router and external entity provider orgs
	// (/organizations/%40opencode) fell through to a broader-scoped route.
	t.Run("it should route a percent encoded path without a trailing slash to the trailing slash route", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve("/organizations/%40opencode").Code)
	})

	t.Run("it should leave a path that already ends in a slash alone", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, serve("/organizations/%40opencode/").Code)
	})

	t.Run("it should keep the query string behind the appended slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/organizations/%40opencode?page=2", nil)
		newServer().ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, "/organizations/%40opencode/?page=2", req.RequestURI)
	})

	t.Run("it should not add a slash to OCI distribution spec routes", func(t *testing.T) {
		rec := serve("/v2/nginx/manifests/latest")

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "oci", rec.Body.String())
	})
}
