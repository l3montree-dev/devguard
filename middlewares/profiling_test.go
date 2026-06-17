package middlewares

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestAddProfileEndpointsBasicAuth(t *testing.T) {
	const password = "supersecret"

	t.Setenv("PPROF_PASSWORD", password)

	t.Run("rejects request without credentials", func(t *testing.T) {
		e := echo.New()
		AddProfileEndpoints(e)

		req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, `Basic realm="pprof"`, rec.Header().Get("WWW-Authenticate"))
	})

	t.Run("rejects request with wrong password", func(t *testing.T) {
		e := echo.New()
		AddProfileEndpoints(e)

		req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
		req.SetBasicAuth("user", "wrongpassword")
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("allows request with correct password", func(t *testing.T) {
		e := echo.New()
		AddProfileEndpoints(e)

		req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
		req.SetBasicAuth("anyuser", password)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("allows any username with correct password", func(t *testing.T) {
		e := echo.New()
		AddProfileEndpoints(e)

		for _, user := range []string{"admin", "foo", "", "tim"} {
			req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
			req.SetBasicAuth(user, password)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusOK, rec.Code, "username %q should be accepted", user)
		}
	})
}

func TestAddProfileEndpointsNoAuth(t *testing.T) {
	t.Setenv("PPROF_PASSWORD", "")

	t.Run("allows unauthenticated access when PPROF_PASSWORD is unset", func(t *testing.T) {
		e := echo.New()
		AddProfileEndpoints(e)

		req := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})
}
