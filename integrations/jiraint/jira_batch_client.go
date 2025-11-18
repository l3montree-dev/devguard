// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"fmt"
	"strings"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/jira"
	"github.com/l3montree-dev/devguard/utils"
)

type jiraBatchClient struct {
	clients []jira.Client
}

var ErrNoJiraIntegration = fmt.Errorf("no Jira integration found")

func NewJiraBatchClient(jiraIntegrations []models.JiraIntegration) (*jiraBatchClient, error) {
	if len(jiraIntegrations) == 0 {
		return nil, ErrNoJiraIntegration
	}

	clients := make([]jira.Client, 0)
	for _, jiraIntegration := range jiraIntegrations {
		client := jira.Client{
			JiraIntegrationID: jiraIntegration.ID,
			AccessToken:       jiraIntegration.AccessToken,
			BaseURL:           jiraIntegration.URL,
			UserEmail:         jiraIntegration.UserEmail,
		}
		clients = append(clients, client)
	}

	return &jiraBatchClient{
		clients: clients,
	}, nil
}

func (c *jiraBatchClient) ListRepositories(search string) ([]jiraRepository, error) {
	wg := utils.ErrGroup[[]jiraRepository](10)

	for _, client := range c.clients {
		wg.Go(func() ([]jiraRepository, error) {

			result, err := client.FetchAllRepos()
			if err != nil {
				return nil, err
			}

			// filter the result set based on the search query
			if search != "" {
				result = utils.Filter(result, func(el *jira.Project) bool {
					return strings.Contains(el.Name, search)
				})
			}

			return utils.Map(result, func(el *jira.Project) jiraRepository {
				return jiraRepository{el, client.JiraIntegrationID}
			}), nil

		})
	}

	results, err := wg.WaitAndCollect()
	if err != nil {
		return nil, err
	}
	return utils.Flat(results), nil
}
