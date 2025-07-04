package gitlabint

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/common"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/pkg/errors"
	gitlab "gitlab.com/gitlab-org/api/client-go"
)

type SimpleGitlabClientFactory struct {
	gitlabIntegrationRepository core.GitlabIntegrationRepository
	oauth2GitlabIntegration     map[string]*GitlabOauth2Config
}

func NewGitlabClientFactory(gitlabIntegrationRepository core.GitlabIntegrationRepository, oauth2GitlabIntegration map[string]*GitlabOauth2Config) SimpleGitlabClientFactory {
	return SimpleGitlabClientFactory{
		gitlabIntegrationRepository: gitlabIntegrationRepository,
		oauth2GitlabIntegration:     oauth2GitlabIntegration,
	}
}

func (factory SimpleGitlabClientFactory) FromIntegration(integration models.GitLabIntegration) (core.GitlabClientFacade, error) {
	// Use installation transport with client.
	client, err := gitlab.NewClient(integration.AccessToken, gitlab.WithBaseURL(integration.GitLabURL))
	if err != nil {
		return gitlabClient{}, err
	}

	return gitlabClient{
		Client:   client,
		clientID: integration.ID.String(),
	}, nil
}

func (factory SimpleGitlabClientFactory) FromIntegrationUUID(id uuid.UUID) (core.GitlabClientFacade, error) {
	integration, err := factory.gitlabIntegrationRepository.Read(id)
	if err != nil {
		return nil, err
	}

	return factory.FromIntegration(integration)
}

func (factory SimpleGitlabClientFactory) FromOauth2Token(token models.GitLabOauth2Token, enableClientCache bool) (core.GitlabClientFacade, error) {
	// get the correct gitlab oauth2 integration configuration
	for _, integration := range factory.oauth2GitlabIntegration {
		if integration.ProviderID == token.ProviderID {
			oauth2Client := integration.client(token)
			// do request deduplication
			common.WrapHTTPClient(oauth2Client, httpRequestDeduplication.Handler())

			if enableClientCache {
				common.WrapHTTPClient(oauth2Client, httpClientCache.Handler())
			}

			client, err := gitlab.NewClient(token.AccessToken, gitlab.WithHTTPClient(oauth2Client), gitlab.WithBaseURL(integration.GitlabBaseURL))
			if err != nil {
				return gitlabOauth2Client{}, err
			}

			return gitlabOauth2Client{
				gitlabUserID: token.GitLabUserID,
				gitlabClient: gitlabClient{Client: client, clientID: fmt.Sprintf("oauth2-%s", token.ID.String()), gitProviderID: utils.Ptr(integration.ProviderID)}}, nil
		}
	}
	return nil, errors.New("could not find gitlab oauth2 integration")
}

func (factory SimpleGitlabClientFactory) FromAccessToken(accessToken string, baseURL string) (core.GitlabClientFacade, error) {
	if accessToken == "" {
		return nil, errors.New("access token is empty")
	}
	if baseURL == "" {
		return nil, errors.New("base URL is empty")
	}
	client, err := gitlab.NewClient(accessToken, gitlab.WithBaseURL(baseURL))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create gitlab client")
	}
	return gitlabClient{Client: client}, nil
}
