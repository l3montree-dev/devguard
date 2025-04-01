package integrations

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/stretchr/testify/assert"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestCreateProjectHook(t *testing.T) {
	t.Run("Returned ProjectHookOption Struct should have the URL set to main devguard", func(t *testing.T) {
		os.Setenv("INSTANCE_DOMAIN", "https://api.main.devguard.org")

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := createProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.main.devguard.org/api/v1/webhook/", *results.URL)

	})
	t.Run("Returned ProjectHookOption Struct should have the URL set to stage devguard if the environment variable INSTANCE_DOMAIN is set to ...staged... ", func(t *testing.T) {

		os.Setenv("INSTANCE_DOMAIN", "https://api.stage.devguard.org")

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := createProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.stage.devguard.org/api/v1/webhook/", *results.URL)

	})
	t.Run("function should default to main if the ENV Variable is empty", func(t *testing.T) {

		os.Setenv("INSTANCE_DOMAIN", "")

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := createProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.main.devguard.org/api/v1/webhook/", *results.URL)

	})
	t.Run("function should default to main if no ENV Variable is provided", func(t *testing.T) {

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := createProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.main.devguard.org/api/v1/webhook/", *results.URL)

	})

	t.Run("function should also work if the user provides the url with a trailing slash", func(t *testing.T) {

		os.Setenv("INSTANCE_DOMAIN", "https://api.stage.devguard.org/")

		hooks := []*gitlab.ProjectHook{}
		token, err := uuid.NewUUID()
		if err != nil {
			slog.Error("error when trying to generate token")
			return
		}
		results, err := createProjectHookOptions(token, hooks)
		if err != nil {
			slog.Error(err.Error())
			return
		}
		assert.Equal(t, "https://api.stage.devguard.org/api/v1/webhook/", *results.URL)

	})
}

func TestTestAndSave(t *testing.T) {
	t.Run("should return error if no token is provided", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", strings.NewReader(`{"url":"localhost:8080/","token":"","name":"GoodName"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		g := gitlabIntegration{}

		err := g.TestAndSave(ctx)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
	})
}
