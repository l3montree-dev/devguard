package integrations

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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
		results, err := createProjectHookOptions(&token, hooks)
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
		results, err := createProjectHookOptions(&token, hooks)
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
		results, err := createProjectHookOptions(&token, hooks)
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
		results, err := createProjectHookOptions(&token, hooks)
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
		results, err := createProjectHookOptions(&token, hooks)
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

func TestIsUserAuthorized(t *testing.T) {
	t.Run("If the provided user is a member of the project we want to return true", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 73573, User: &gitlab.User{ID: 487535}}
		client := mocks.NewGitlabClientFacade(t)
		client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Nil(t, err)
		assert.True(t, isAuthorized)
	})
	t.Run("If the provided user is not a member of the project we want to return false", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 7353, User: &gitlab.User{ID: 487535}}
		client := mocks.NewGitlabClientFacade(t)
		client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything).Return(false, nil)
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Nil(t, err)
		assert.False(t, isAuthorized)
	})
	t.Run("If the participation check of the user in the project runs into an error we also want to return that error", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 7353, User: &gitlab.User{ID: 487535}}
		client := mocks.NewGitlabClientFacade(t)
		client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything).Return(false, fmt.Errorf("the gitlab api was blown up"))
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Equal(t, "the gitlab api was blown up", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the provided user is nil we want to abort", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 7353}
		client := mocks.NewGitlabClientFacade(t)
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Equal(t, "missing event data", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the passed event is nil we also want to abort", func(t *testing.T) {
		isAuthorized, err := isGitlabUserAuthorized(nil, nil)
		assert.Equal(t, "missing event data", err.Error())
		assert.False(t, isAuthorized)
	})
}
