package redmineint

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
)

type redmineBatchClient struct {
	clients []Client
}

var ErrNoRedmineIntegration = fmt.Errorf("no Redmine integration found")

func NewRedmineBatchClient(r shared.RedmineIntegrationRepository, redmineIntegrations []models.RedmineIntegration) (*redmineBatchClient, error) {
	if len(redmineIntegrations) == 0 {
		return nil, ErrNoRedmineIntegration
	}

	clients := make([]Client, 0)
	for _, redmineIntegration := range redmineIntegrations {
		redmineIntegration, err := r.GetClientByIntegrationID(context.Background(), nil, redmineIntegration.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to get Redmine client for integration ID %s: %w", redmineIntegration.ID, err)
		}
		slog.Debug("Creating Redmine client for integration", "integration_id", redmineIntegration.ID, "url", redmineIntegration.URL, "access_token", redmineIntegration.AccessToken)
		client := Client{
			RedmineIntegrationID: redmineIntegration.ID,
			AccessToken:          redmineIntegration.AccessToken,
			BaseURL:              redmineIntegration.URL,
		}
		clients = append(clients, client)
	}

	return &redmineBatchClient{
		clients: clients,
	}, nil
}

func (c *redmineBatchClient) ListRepositories(search string) ([]redmineRepository, error) {
	wg := utils.ErrGroup[[]redmineRepository](10)

	for _, client := range c.clients {
		wg.Go(func() ([]redmineRepository, error) {

			result, err := client.FetchAllRepos(context.Background())
			if err != nil {
				return nil, err
			}

			// filter the result set based on the search query
			if search != "" {
				result = utils.Filter(result, func(el *Project) bool {
					return strings.Contains(el.Name, search)
				})
			}

			return utils.Map(result, func(el *Project) redmineRepository {
				return redmineRepository{el, client.RedmineIntegrationID}
			}), nil
		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}
