// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package jiraint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/utils"
)

type JiraClient struct {
	JiraIntegrationID string
	AccessToken       string
	BaseURL           string
	UserEmail         string
}

type jiraBatchClient struct {
	clients []JiraClient
}

var ErrNoJiraIntegration = fmt.Errorf("no Jira integration found")

func NewJiraBatchClient(jiraIntegrations []models.JiraIntegration) (*jiraBatchClient, error) {
	if len(jiraIntegrations) == 0 {
		return nil, ErrNoJiraIntegration
	}

	clients := make([]JiraClient, 0)
	for _, jiraIntegration := range jiraIntegrations {
		client := JiraClient{
			JiraIntegrationID: jiraIntegration.ID.String(),
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

			result, err := fetchAllRepos(client)
			if err != nil {
				return nil, err
			}

			// filter the result set based on the search query
			if search != "" {
				result = utils.Filter(result, func(el *Project) bool {
					return strings.Contains(el.Name, search)
				})
			}

			return utils.Map(result, func(el *Project) jiraRepository {
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

func fetchAllRepos(client JiraClient) ([]*Project, error) {

	resp, err := jiraRequest(client, http.MethodGet, "/rest/api/3/project", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch projects: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch projects, status code: %d", resp.StatusCode)
	}

	var projects []*Project
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("failed to decode projects response: %w", err)
	}

	for _, project := range projects {
		fmt.Printf("Project ID: %s, Name: %s\n", project.ID, project.Name)
	}

	return projects, nil

}

func jiraRequest(client JiraClient, method string, url string, body io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, client.BaseURL+url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")

	req.SetBasicAuth(client.UserEmail, client.AccessToken)

	return http.DefaultClient.Do(req)
}
