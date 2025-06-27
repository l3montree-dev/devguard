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

func (c *Client) GetAccountIDByEmail(ctx context.Context, email string) (string, error) {
	resp, err := jiraRequest(*c, http.MethodGet, fmt.Sprintf("/rest/api/3/user/search?query=%s", email), nil)
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

func (c *Client) CreateIssueComment(ctx context.Context, issueId string, projectId string, comment string) (string, string, error) {

	fmt.Println("Creating comment for issue:", issueId, "in project:", projectId, "with comment:", comment)

	var commentData = ADF{
		Version: 1,
		Type:    "doc",
		Content: []ADFContent{
			{
				Type: "paragraph",
				Content: []ADFContent{
					{
						Type: "text",
						Text: comment,
					},
				},
			},
		},
	}

	data := map[string]interface{}{
		"body": commentData,
	}

	bodyBytes, err := json.Marshal(data)
	if err != nil {
		slog.Error("Failed to marshal comment data", "error", err)
		return "", "", fmt.Errorf("failed to marshal comment data: %w", err)
	}
	body := bytes.NewBuffer(bodyBytes)

	resp, err := jiraRequest(*c, http.MethodPost, fmt.Sprintf("/rest/api/3/issue/%s/comment", issueId), body)
	if err != nil {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue comment", "error", err, "response_body", string(bodyContent))
		return "", "", fmt.Errorf("failed to create issue comment: %w	", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue comment", "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return "", "", fmt.Errorf("failed to create issue comment, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	slog.Info("Issue comment created successfully", "issue_id", issueId, "project_id", projectId, "response_status", resp.StatusCode, "response_body", bodyBytes)

	return "", "", nil
}
func (c *Client) CreateIssue(ctx context.Context, issue *Issue) (*CreateIssueResponse, string, error) {
	// Marshal the issue struct to JSON
	bodyBytes, err := json.Marshal(issue)
	if err != nil {
		slog.Error("Failed to marshal issue", "error", err)
		return nil, "", fmt.Errorf("failed to marshal issue: %w", err)
	}

	body := bytes.NewBuffer(bodyBytes)

	resp, err := jiraRequest(*c, http.MethodPost, "/rest/api/3/issue", body)
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
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue", "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return nil, "", fmt.Errorf("failed to create issue, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	return &response, response.ID, nil

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

	slog.Info("Jira response body ",
		"status", resp.StatusCode,
		"headers", resp.Header,
		"body", resp.Body,
	)

	var projects []*Project
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("failed to decode projects response: %w", err)
	}

	for _, project := range projects {
		fmt.Println("Project ID:", project)
	}

	return projects, nil
}

func jiraRequest(client Client, method string, url string, body io.Reader) (*http.Response, error) {

	fmt.Println("body comment", body)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, client.BaseURL+url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	req.SetBasicAuth(client.UserEmail, client.AccessToken)
	return http.DefaultClient.Do(req)
	/* 	respBody, _ := io.ReadAll(resp.Body)
	   	if err != nil {
	   		slog.Info("Jira request failed ",
	   			"method", method,
	   			"url", url,
	   			"status", resp.StatusCode,
	   			"response", string(respBody),
	   		)
	   		return nil, fmt.Errorf("failed to execute request: %w %s", err, string(respBody))
	   	}

	   	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
	   		slog.Info("Jira request failed ",
	   			"method", method,
	   			"url", url,
	   			"status", resp.StatusCode,
	   			"response", string(respBody),
	   		)
	   		return nil, fmt.Errorf("request failed with status code %d: %s", resp.StatusCode, string(respBody))
	   	}

	   	slog.Info("Jira request successful",
	   		"method", method,
	   		"url", url,
	   		"status", resp.StatusCode,
	   		"response", string(respBody),
	   	) */

}

func ParseWebHook(payload []byte) (*WebhookEvent, error) {

	fmt.Println("Parsing webhook payload:", string(payload))

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
