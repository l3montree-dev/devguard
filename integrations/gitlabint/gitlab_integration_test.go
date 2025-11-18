package gitlabint

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/integrations/commonint"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func TestCreateProjectHook(t *testing.T) {
	t.Run("Returned ProjectHookOption Struct should have the URL set to main devguard", func(t *testing.T) {
		os.Setenv("INSTANCE_DOMAIN", "https://api.devguard.org")

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
		assert.Equal(t, "https://api.devguard.org/api/v1/webhook/", *results.URL)

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
	t.Run("Returned ProjectHookOption Struct should have the URL set to localhost if INSTANCE_DOMAIN is set to localhost - and enable ssl set to false", func(t *testing.T) {

		os.Setenv("INSTANCE_DOMAIN", "http://localhost:8080")

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
		assert.Equal(t, "http://localhost:8080/api/v1/webhook/", *results.URL)
		assert.Equal(t, false, *results.EnableSSLVerification)
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
		assert.Equal(t, "https://api.devguard.org/api/v1/webhook/", *results.URL)

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
		assert.Equal(t, "https://api.devguard.org/api/v1/webhook/", *results.URL)

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

		g := GitlabIntegration{}

		err := g.TestAndSave(ctx)

		assert.Nil(t, err)
		assert.Equal(t, http.StatusBadRequest, rec.Result().StatusCode)
	})
}

func TestIsGitlabUserAuthorized(t *testing.T) {
	t.Run("If the provided user is a member of the project we want to return true", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 73573, User: &gitlab.User{ID: 487535}}
		client := mocks.NewGitlabClientFacade(t)
		client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, nil)
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Nil(t, err)
		assert.True(t, isAuthorized)
	})
	t.Run("If the provided user is not a member of the project we want to return false", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 7353, User: &gitlab.User{ID: 487535}}
		client := mocks.NewGitlabClientFacade(t)
		client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, nil)
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Nil(t, err)
		assert.False(t, isAuthorized)
	})
	t.Run("If the participation check of the user in the project runs into an error we also want to return that error", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 7353, User: &gitlab.User{ID: 487535}}
		client := mocks.NewGitlabClientFacade(t)
		client.On("IsProjectMember", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, fmt.Errorf("the gitlab api was blown up"))
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Equal(t, "the gitlab api was blown up", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the provided user is nil we want to abort", func(t *testing.T) {
		event := gitlab.IssueCommentEvent{ProjectID: 7353}
		client := mocks.NewGitlabClientFacade(t)
		isAuthorized, err := isGitlabUserAuthorized(&event, client)
		assert.Equal(t, "missing event data, could not resolve if user is authorized", err.Error())
		assert.False(t, isAuthorized)
	})
	t.Run("If the passed event is nil we also want to abort", func(t *testing.T) {
		isAuthorized, err := isGitlabUserAuthorized(nil, nil)
		assert.Equal(t, "missing event data, could not resolve if user is authorized", err.Error())
		assert.False(t, isAuthorized)
	})
}

func TestCreateLabels(t *testing.T) {
	t.Run("should successfully create labels when asset has repositoryID with gitlab prefix", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Mock label creation for all risk labels
		labels := commonint.GetAllRiskLabelsWithColors()
		for _, label := range labels {
			labelName := label.Name
			labelColor := label.Color
			labelDescription := label.Description
			mockClient.On("CreateNewLabel", ctx, projectID, mock.MatchedBy(func(opts *gitlab.CreateLabelOptions) bool {
				return *opts.Name == labelName && *opts.Color == labelColor && *opts.Description == labelDescription
			})).Return(&gitlab.Label{}, &gitlab.Response{}, nil).Times(1)
		}

		// Execute
		err := integration.CreateLabels(ctx, asset)

		// Assert
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should successfully create labels when asset has externalEntityProviderID", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
			oauth2Endpoints: map[string]*GitlabOauth2Config{
				"test-provider": {
					DevGuardBotUserAccessToken: "test-token",
					GitlabBaseURL:              "https://gitlab.com",
				},
			},
		}

		asset := models.Asset{
			ExternalEntityProviderID: stringPtr("test-provider"),
			ExternalEntityID:         stringPtr("123"),
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromAccessToken", "test-token", "https://gitlab.com").Return(mockClient, nil)

		// Mock label creation for all risk labels
		labels := commonint.GetAllRiskLabelsWithColors()
		for _, label := range labels {
			labelName := label.Name
			labelColor := label.Color
			labelDescription := label.Description
			mockClient.On("CreateNewLabel", ctx, projectID, mock.MatchedBy(func(opts *gitlab.CreateLabelOptions) bool {
				return *opts.Name == labelName && *opts.Color == labelColor && *opts.Description == labelDescription
			})).Return(&gitlab.Label{}, &gitlab.Response{}, nil).Times(1)
		}

		// Execute
		err := integration.CreateLabels(ctx, asset)

		// Assert
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should update existing labels when they already exist", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Get all labels and set up mocks
		labels := commonint.GetAllRiskLabelsWithColors()

		// Mock all labels: first 6 succeed, last 2 already exist (409 conflict)
		for i := 0; i < 6; i++ {
			labelName := labels[i].Name
			mockClient.On("CreateNewLabel", ctx, projectID, mock.MatchedBy(func(opts *gitlab.CreateLabelOptions) bool {
				return *opts.Name == labelName
			})).Return(&gitlab.Label{}, &gitlab.Response{}, nil)
		}

		// Last 2 labels already exist (409 conflict)
		for i := 6; i < len(labels); i++ {
			labelName := labels[i].Name
			mockClient.On("CreateNewLabel", ctx, projectID, mock.MatchedBy(func(opts *gitlab.CreateLabelOptions) bool {
				return *opts.Name == labelName
			})).Return(nil, nil, errors.New(" 409 {message: Label already exists}"))
		}

		// Mock UpdateLabels call for the conflicting labels (labels 6 and 7)
		existingLabels := []*gitlab.Label{
			{ID: 6, Name: labels[6].Name},
			{ID: 7, Name: labels[7].Name},
		}
		mockClient.On("ListLabels", ctx, projectID, &gitlab.ListLabelsOptions{}).Return(existingLabels, &gitlab.Response{}, nil)

		// Mock updates for both conflicting labels
		httpResponse := &http.Response{StatusCode: 200}
		response := &gitlab.Response{Response: httpResponse}
		mockClient.On("UpdateLabel", ctx, projectID, 6, mock.MatchedBy(func(opts *gitlab.UpdateLabelOptions) bool {
			return *opts.Color == labels[6].Color && *opts.Description == labels[6].Description
		})).Return(&gitlab.Label{}, response, nil)

		mockClient.On("UpdateLabel", ctx, projectID, 7, mock.MatchedBy(func(opts *gitlab.UpdateLabelOptions) bool {
			return *opts.Color == labels[7].Color && *opts.Description == labels[7].Description
		})).Return(&gitlab.Label{}, response, nil)

		// Execute
		err := integration.CreateLabels(ctx, asset)

		// Assert
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should return nil when asset is not connected to gitlab", func(t *testing.T) {
		// Setup
		integration := &GitlabIntegration{}

		asset := models.Asset{
			// No RepositoryID or ExternalEntityProviderID
		}

		ctx := context.Background()

		// Execute
		err := integration.CreateLabels(ctx, asset)

		// Assert
		assert.NoError(t, err) // Should return nil, not error
	})

	t.Run("should return error when client factory fails", func(t *testing.T) {
		// Setup
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		ctx := context.Background()

		// Mock client creation failure
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(nil, errors.New("failed to create client"))

		// Execute
		err := integration.CreateLabels(ctx, asset)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create gitlab client")
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should return error when label creation fails", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Mock label creation failure
		labels := commonint.GetAllRiskLabelsWithColors()
		labelName := labels[0].Name
		mockClient.On("CreateNewLabel", ctx, projectID, mock.MatchedBy(func(opts *gitlab.CreateLabelOptions) bool {
			return *opts.Name == labelName
		})).Return(nil, nil, errors.New("gitlab api error"))

		// Execute
		err := integration.CreateLabels(ctx, asset)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "gitlab api error")
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})
}

func TestUpdateLabels(t *testing.T) {
	t.Run("should successfully update existing labels", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		labelsToUpdate := []commonint.Label{
			{
				Name:        "risk:high",
				Color:       "#FF0000",
				Description: "High risk vulnerability",
			},
			{
				Name:        "risk:medium",
				Color:       "#FFA500",
				Description: "Medium risk vulnerability",
			},
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Mock existing labels in project
		existingLabels := []*gitlab.Label{
			{
				ID:   1,
				Name: "risk:high",
			},
			{
				ID:   2,
				Name: "risk:medium",
			},
			{
				ID:   3,
				Name: "other:label",
			},
		}

		mockClient.On("ListLabels", ctx, projectID, &gitlab.ListLabelsOptions{}).Return(existingLabels, &gitlab.Response{}, nil)

		// Mock label updates
		httpResponse := &http.Response{StatusCode: 200}
		response := &gitlab.Response{Response: httpResponse}
		mockClient.On("UpdateLabel", ctx, projectID, 1, mock.MatchedBy(func(opts *gitlab.UpdateLabelOptions) bool {
			return *opts.Color == labelsToUpdate[0].Color && *opts.Description == labelsToUpdate[0].Description
		})).Return(&gitlab.Label{}, response, nil)
		mockClient.On("UpdateLabel", ctx, projectID, 2, mock.MatchedBy(func(opts *gitlab.UpdateLabelOptions) bool {
			return *opts.Color == labelsToUpdate[1].Color && *opts.Description == labelsToUpdate[1].Description
		})).Return(&gitlab.Label{}, response, nil)

		// Execute
		err := integration.UpdateLabels(ctx, asset, labelsToUpdate)

		// Assert
		assert.NoError(t, err)
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should return nil when labels to update list is empty", func(t *testing.T) {
		// Setup
		integration := &GitlabIntegration{}
		asset := models.Asset{}
		ctx := context.Background()

		// Execute
		err := integration.UpdateLabels(ctx, asset, []commonint.Label{})

		// Assert
		assert.NoError(t, err)
	})

	t.Run("should return nil when asset is not connected to gitlab", func(t *testing.T) {
		// Setup
		integration := &GitlabIntegration{}

		asset := models.Asset{
			// No RepositoryID or ExternalEntityProviderID
		}

		labelsToUpdate := []commonint.Label{
			{Name: "test", Color: "#FF0000", Description: "test"},
		}

		ctx := context.Background()

		// Execute
		err := integration.UpdateLabels(ctx, asset, labelsToUpdate)

		// Assert
		assert.NoError(t, err) // Should return nil, not error
	})

	t.Run("should return error when client factory fails", func(t *testing.T) {
		// Setup
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		labelsToUpdate := []commonint.Label{
			{Name: "test", Color: "#FF0000", Description: "test"},
		}

		ctx := context.Background()

		// Mock client creation failure
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(nil, errors.New("failed to create client"))

		// Execute
		err := integration.UpdateLabels(ctx, asset, labelsToUpdate)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create gitlab client")
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should return error when listing labels fails", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		labelsToUpdate := []commonint.Label{
			{Name: "test", Color: "#FF0000", Description: "test"},
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Mock listing labels failure
		mockClient.On("ListLabels", ctx, projectID, &gitlab.ListLabelsOptions{}).Return(nil, nil, errors.New("failed to list labels"))

		// Execute
		err := integration.UpdateLabels(ctx, asset, labelsToUpdate)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list labels")
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should return error when updating label fails", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		labelsToUpdate := []commonint.Label{
			{
				Name:        "risk:high",
				Color:       "#FF0000",
				Description: "High risk vulnerability",
			},
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Mock existing labels in project
		existingLabels := []*gitlab.Label{
			{
				ID:   1,
				Name: "risk:high",
			},
		}

		mockClient.On("ListLabels", ctx, projectID, &gitlab.ListLabelsOptions{}).Return(existingLabels, &gitlab.Response{}, nil)

		// Mock label update failure
		mockClient.On("UpdateLabel", ctx, projectID, 1, mock.MatchedBy(func(opts *gitlab.UpdateLabelOptions) bool {
			return *opts.Color == labelsToUpdate[0].Color && *opts.Description == labelsToUpdate[0].Description
		})).Return(nil, nil, errors.New("failed to update label"))

		// Execute
		err := integration.UpdateLabels(ctx, asset, labelsToUpdate)

		// Assert
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update label")
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})

	t.Run("should skip labels that don't exist in project", func(t *testing.T) {
		// Setup
		mockClient := mocks.NewGitlabClientFacade(t)
		mockClientFactory := mocks.NewGitlabClientFactory(t)

		integration := &GitlabIntegration{
			clientFactory: mockClientFactory,
		}

		asset := models.Asset{
			RepositoryID: stringPtr("gitlab:550e8400-e29b-41d4-a716-446655440000:123"),
		}

		labelsToUpdate := []commonint.Label{
			{
				Name:        "risk:high",
				Color:       "#FF0000",
				Description: "High risk vulnerability",
			},
			{
				Name:        "non-existent",
				Color:       "#000000",
				Description: "This label doesn't exist",
			},
		}

		ctx := context.Background()
		projectID := 123

		// Mock client creation
		mockClientFactory.On("FromIntegrationUUID", uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")).Return(mockClient, nil)

		// Mock existing labels in project (only risk:high exists)
		existingLabels := []*gitlab.Label{
			{
				ID:   1,
				Name: "risk:high",
			},
		}

		mockClient.On("ListLabels", ctx, projectID, &gitlab.ListLabelsOptions{}).Return(existingLabels, &gitlab.Response{}, nil)

		// Mock label update for only the existing label
		httpResponse := &http.Response{StatusCode: 200}
		response := &gitlab.Response{Response: httpResponse}
		mockClient.On("UpdateLabel", ctx, projectID, 1, mock.MatchedBy(func(opts *gitlab.UpdateLabelOptions) bool {
			return *opts.Color == labelsToUpdate[0].Color && *opts.Description == labelsToUpdate[0].Description
		})).Return(&gitlab.Label{}, response, nil)

		// Execute
		err := integration.UpdateLabels(ctx, asset, labelsToUpdate)

		// Assert
		assert.NoError(t, err) // Should not error, just skip non-existent label
		mockClient.AssertExpectations(t)
		mockClientFactory.AssertExpectations(t)
	})
}

// Helper function for creating string pointers
func stringPtr(s string) *string {
	return &s
}
