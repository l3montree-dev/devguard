package tests

import (
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
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

func (f TestGitlabClientFactory) FromAccessToken(accessToken string, baseURL string) (shared.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f TestGitlabClientFactory) FromIntegration(integration models.GitLabIntegration) (shared.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f TestGitlabClientFactory) FromIntegrationUUID(id uuid.UUID) (shared.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}

func (f TestGitlabClientFactory) FromOauth2Token(token models.GitLabOauth2Token, enableClientCache bool) (shared.GitlabClientFacade, error) {
	return f.GitlabClientFacade, nil
}
