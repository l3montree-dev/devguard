package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/database/models"
)

type Client struct {
	JiraIntegrationID uuid.UUID
	AccessToken       string
	BaseURL           string
	UserEmail         string
}

func (c *Client) SetJiraIntegrationID(id uuid.UUID) {
	c.JiraIntegrationID = id
}

func NewJiraClient(token string, baseURL string, userEmail string) (*Client, error) {
	if token == "" || baseURL == "" || userEmail == "" {
		return nil, fmt.Errorf("invalid Jira client parameters: token, baseURL, and userEmail must be provided")
	}
	return &Client{
		AccessToken: token,
		BaseURL:     baseURL,
		UserEmail:   userEmail,
	}, nil
}

func (c *Client) GetAccountIDByEmail(ctx context.Context, email string) (string, error) {

	fmt.Println("Fetching user by email:", email)

	resp, err := jiraRequest(*c, http.MethodGet, fmt.Sprintf("/rest/api/3/user/search?query=%s", email), nil)
	if err != nil {
		return "", fmt.Errorf("failed to fetch user by email: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		fmt.Println("JIRA response body:", string(respBody))
		return "", fmt.Errorf("failed to fetch user by email, status code: %d", resp.StatusCode)
	}

	var user []User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		return "", fmt.Errorf("failed to decode user response: %w", err)
	}

	if len(user) == 0 {
		return "", fmt.Errorf("no user found with email: %s", email)
	}

	if len(user) > 1 {
		fmt.Println("Multiple users found with the same email, returning the first one.")
	}

	return user[0].AccountID, nil

}

func (c *Client) CreateIssueComment(ctx context.Context, asset models.Asset, vuln models.Vuln, issueId string, projectId string, comment string) (string, string, error) {
	return "", "", fmt.Errorf("not implemented")
}
func (c *Client) CreateIssue(ctx context.Context, issue *Issue) (string, string, error) {
	// Marshal the issue struct to JSON
	bodyBytes, err := json.Marshal(issue)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal issue: %w", err)
	}

	fmt.Println(bodyBytes)

	body := bytes.NewBuffer(bodyBytes)
	fmt.Println("Creating issue with body:", body)

	repo, err := jiraRequest(*c, http.MethodPost, "/rest/api/3/issue", body)
	if err != nil {
		return "", "", fmt.Errorf("failed to create issue: %w", err)
	}
	defer repo.Body.Close()

	fmt.Println("Response status:", repo.Status)
	fmt.Println("Response headers:", repo.Header)

	respBody, _ := io.ReadAll(repo.Body)
	fmt.Println("JIRA response body:", string(respBody))

	return "", "", fmt.Errorf("not implemented")
}

func (c *Client) FetchAllRepos() ([]*Project, error) {

	resp, err := jiraRequest(*c, http.MethodGet, "/rest/api/3/project", nil)
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

func jiraRequest(client Client, method string, url string, body io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	u := client.BaseURL + url
	fmt.Println("Making request to:", u)
	req, err := http.NewRequestWithContext(ctx, method, client.BaseURL+url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	req.SetBasicAuth(client.UserEmail, client.AccessToken)

	return http.DefaultClient.Do(req)
}
