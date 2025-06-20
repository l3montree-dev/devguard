package integration_tests

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
)

type TestGitlabClientFactory struct {
	*mocks.GitlabClientFacade
}

func NewTestClientFactory(t *testing.T) (TestGitlabClientFactory, *mocks.GitlabClientFacade) {
	client := mocks.NewGitlabClientFacade(t)
	return TestGitlabClientFactory{
		GitlabClientFacade: client,
	}, client
}

func (f TestGitlabClientFactory) FromAccessToken(accessToken string, baseURL string) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f TestGitlabClientFactory) FromIntegration(integration models.GitLabIntegration) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f TestGitlabClientFactory) FromIntegrationUUID(id uuid.UUID) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f TestGitlabClientFactory) FromOauth2Token(token models.GitLabOauth2Token, enableClientCache bool) (core.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}
