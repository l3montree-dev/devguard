package jira

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
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

func (c *Client) GetIssueTransitions(ctx context.Context, issueID string) ([]Transition, error) {
	resp, err := c.jiraRequest(http.MethodGet, fmt.Sprintf("/rest/api/3/issue/%s/transitions", issueID), nil)
	if err != nil {
		slog.Error("Failed to fetch issue transitions", "issue_id", issueID, "error", err)
		return nil, fmt.Errorf("failed to fetch issue transitions: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Error("Failed to fetch issue transitions", "issue_id", issueID, "status_code", resp.StatusCode)
		return nil, fmt.Errorf("failed to fetch issue transitions, status code: %d", resp.StatusCode)
	}

	var transitions TransitionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&transitions); err != nil {
		slog.Error("Failed to decode transitions response", "issue_id", issueID, "error", err)
		return nil, fmt.Errorf("failed to decode transitions response: %w", err)
	}

	slog.Info("Fetched issue transitions successfully", "issue_id", issueID, "transitions_count", len(transitions.Transitions))

	return transitions.Transitions, nil
}

func (c *Client) GetAccountIDByEmail(ctx context.Context, email string) (string, error) {
	resp, err := c.jiraRequest(http.MethodGet, fmt.Sprintf("/rest/api/3/user/search?query=%s", email), nil)
	if err != nil {
		slog.Error("Failed to fetch user by email", "email", email, "error", err)
		return "", fmt.Errorf("failed to fetch user by email: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		slog.Error("Failed to fetch user by email", "email", email, "status_code", resp.StatusCode)
		return "", fmt.Errorf("failed to fetch user by email, status code: %d", resp.StatusCode)
	}

	var user []User
	if err := json.NewDecoder(resp.Body).Decode(&user); err != nil {
		slog.Error("Failed to decode user response", "email", email, "error", err)
		return "", fmt.Errorf("failed to decode user response: %w", err)
	}

	if len(user) == 0 {
		slog.Error("No user found with the provided email", "email", email)
		return "", fmt.Errorf("no user found with email: %s", email)
	}

	if len(user) > 1 {
		slog.Warn("Multiple users found with the same email, returning the first one", "email", email)
	}

	return user[0].AccountID, nil

}

func (c *Client) CreateIssueComment(ctx context.Context, issueID string, projectID string, comment ADF) error {

	data := map[string]interface{}{
		"body": comment,
	}

	bodyBytes, err := json.Marshal(data)
	if err != nil {
		slog.Error("Failed to marshal comment data", "error", err)
		return fmt.Errorf("failed to marshal comment data: %w", err)
	}
	body := bytes.NewBuffer(bodyBytes)

	resp, err := c.jiraRequest(http.MethodPost, fmt.Sprintf("/rest/api/3/issue/%s/comment", issueID), body)
	if err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue comment", "error", err, "response_body", string(bodyContent))
		return fmt.Errorf("failed to create issue comment: %w	", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue comment", "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return fmt.Errorf("failed to create issue comment, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	slog.Info("Issue comment created successfully", "issue_id", issueID, "project_id", projectID)

	return nil
}

func (c *Client) TransitionIssue(ctx context.Context, issueID string, transitionID string) error {
	// Create the request body for the transition
	body := map[string]interface{}{
		"transition": map[string]string{
			"id": transitionID,
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		slog.Error("Failed to marshal transition body", "error", err)
		return fmt.Errorf("failed to marshal transition body: %w", err)
	}

	resp, err := c.jiraRequest(http.MethodPost, fmt.Sprintf("/rest/api/3/issue/%s/transitions", issueID), bytes.NewBuffer(bodyBytes))
	if err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to transition issue", "issue_id", issueID, "error", err, "response_body", string(bodyContent))
		return fmt.Errorf("failed to transition issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to transition issue", "issue_id", issueID, "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return fmt.Errorf("failed to transition issue, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	slog.Info("Issue transitioned successfully", "issue_id", issueID, "transition_id", transitionID, "response_status", resp.StatusCode)
	return nil
}

func (c *Client) EditIssue(ctx context.Context, issue *Issue) error {
	// Marshal the issue struct to JSON
	bodyBytes, err := json.Marshal(issue)
	if err != nil {
		slog.Error("Failed to marshal issue", "error", err)
		return fmt.Errorf("failed to marshal issue: %w", err)
	}
	body := bytes.NewBuffer(bodyBytes)
	resp, err := c.jiraRequest(http.MethodPut, fmt.Sprintf("/rest/api/3/issue/%s", issue.ID), body)
	if err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to edit issue", "error", err, "response_body", string(bodyContent))
		return fmt.Errorf("failed to edit issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to edit issue", "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return fmt.Errorf("failed to edit issue, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	slog.Info("Issue edited successfully", "issue_id", issue.ID, "response_status", resp.StatusCode)
	return nil
}

func (c *Client) GetIssue(ctx context.Context, issueID string) (*Issue, error) {
	resp, err := c.jiraRequest(http.MethodGet, fmt.Sprintf("/rest/api/3/issue/%s", issueID), nil)
	if err != nil {
		slog.Error("Failed to fetch issue", "issue_id", issueID, "error", err)
		return nil, fmt.Errorf("failed to fetch issue: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to fetch issue", "issue_id", issueID, "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return nil, fmt.Errorf("failed to fetch issue, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	var issue Issue
	if err := json.NewDecoder(resp.Body).Decode(&issue); err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to decode issue response", "issue_id", issueID, "error", err, "response_body", string(bodyContent))
		return nil, fmt.Errorf("failed to decode issue response: %w", err)
	}

	slog.Info("Fetched issue successfully", "issue_id", issueID, "response_status", resp.StatusCode)
	return &issue, nil
}

func (c *Client) CreateIssue(ctx context.Context, issue *Issue) (*CreateIssueResponse, string, error) {
	// Marshal the issue struct to JSON
	bodyBytes, err := json.Marshal(issue)
	if err != nil {
		slog.Error("Failed to marshal issue", "error", err)
		return nil, "", fmt.Errorf("failed to marshal issue: %w", err)
	}

	body := bytes.NewBuffer(bodyBytes)

	resp, err := c.jiraRequest(http.MethodPost, "/rest/api/3/issue", body)
	if err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue", "error", err, "response_body", string(bodyContent))
		return nil, "", fmt.Errorf("failed to create issue: %w", err)
	}
	defer resp.Body.Close()

	var response CreateIssueResponse

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to decode issue creation response", "error", err, "response_body", string(bodyContent))

		return nil, "", fmt.Errorf("failed to decode issue creation response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		slog.Error("Failed to create issue", "status_code", resp.StatusCode, "error_message", response.ErrorMessages)
		return nil, "", fmt.Errorf("failed to create issue, status code: %d, response: %s", resp.StatusCode, response.ErrorMessages)
	}

	return &response, response.ID, nil

}

func (c *Client) FetchAllRepos() ([]*Project, error) {

	resp, err := c.jiraRequest(http.MethodGet, "/rest/api/3/project", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch projects: %w", err)
	}

	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch projects, status code: %d", resp.StatusCode)
	}

	slog.Info("Jira response body ",
		"status", resp.StatusCode,
		"headers", resp.Header,
		"body", resp.Body,
	)

	var projects []*Project
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("failed to decode projects response: %w", err)
	}

	return projects, nil
}

func (c *Client) jiraRequest(method string, url string, body io.Reader) (*http.Response, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	req.SetBasicAuth(c.UserEmail, c.AccessToken)
	return http.DefaultClient.Do(req)

}

func ParseWebhook(payload []byte) (*WebhookEvent, error) {

	var event WebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		slog.Error("Failed to parse webhook payload", "error", err)
		return nil, fmt.Errorf("failed to parse webhook payload: %w", err)
	}

	if event.Event == "" {
		slog.Error("Webhook event type is empty")
		return nil, fmt.Errorf("webhook event type is empty")
	}

	slog.Info("Parsed webhook event", "event", event.Event)

	return &event, nil
}
