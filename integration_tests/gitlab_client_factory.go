package integration_tests

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
)

type testGitlabClientFactory struct {
	*mocks.GitlabClientFacade
}

func NewTestClientFactory(t *testing.T) (testGitlabClientFactory, *mocks.GitlabClientFacade) {
	client := mocks.NewGitlabClientFacade(t)
	return testGitlabClientFactory{
		GitlabClientFacade: client,
	}, client
}

func (f testGitlabClientFactory) FromAccessToken(accessToken string, baseUrl string) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f testGitlabClientFactory) FromIntegration(integration models.GitLabIntegration) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f testGitlabClientFactory) FromIntegrationUUID(id uuid.UUID) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f testGitlabClientFactory) FromOauth2Token(token models.GitLabOauth2Token, enableClientCache bool) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}
