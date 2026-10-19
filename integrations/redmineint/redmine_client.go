package redmineint

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/utils"
)

type Client struct {
	RedmineIntegrationID uuid.UUID
	AccessToken          string
	BaseURL              string
}

func (c *Client) SetRedmineIntegrationID(id uuid.UUID) {
	c.RedmineIntegrationID = id
}

func NewRedmineClient(token string, baseURL string) (*Client, error) {
	if token == "" || baseURL == "" {
		return nil, fmt.Errorf("invalid Redmine client parameters: token and baseURL must be provided")
	}

	return &Client{
		AccessToken: token,
		BaseURL:     baseURL,
	}, nil
}

func (c *Client) FetchAllRepos(ctx context.Context) ([]*Project, error) {
	var projects []*Project
	for {
		pageProjects, err := c.FetchRepos(ctx, len(projects), 100)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch projects: %w", err)
		}

		projects = append(projects, pageProjects...)

		if len(pageProjects) < 100 {
			break
		}
	}

	return projects, nil
}

func (c *Client) FetchRepos(ctx context.Context, offset int, limit int) ([]*Project, error) {
	if offset < 0 || limit <= 0 || limit > 100 {
		return nil, fmt.Errorf("invalid offset or limit: offset must be >= 0 and limit must be > 0 and <= 100")
	}

	query := map[string]string{
		"offset": fmt.Sprintf("%d", offset),
		"limit":  fmt.Sprintf("%d", limit),
	}

	resp, err := c.redmineRequest(ctx, http.MethodGet, "/projects.json", query, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch projects: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch projects, status code: %d", resp.StatusCode)
	}

	var response ProjectsResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode projects response: %w", err)
	}

	return response.Projects, nil
}

func (c *Client) CreateIssue(ctx context.Context, issue *IssueCreateOptions) (*Issue, error) {
	bodyBytes, err := json.Marshal(IssueCreateRequest{Issue: issue})
	if err != nil {
		slog.Error("Failed to marshal issue", "error", err)
		return nil, fmt.Errorf("failed to marshal issue: %w", err)
	}

	slog.Debug("Creating issue", "issue", string(bodyBytes))
	body := bytes.NewBuffer(bodyBytes)

	resp, err := c.redmineRequest(ctx, http.MethodPost, "/issues.json", nil, body)
	if err != nil {
		slog.Error("Failed to create issue", "error", err)

		return nil, fmt.Errorf("failed to create issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to create issue", "status_code", resp.StatusCode, "error_message", string(bodyContent))

		return nil, fmt.Errorf("failed to create issue, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	var response IssueResponse

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		slog.Error("Failed to decode issue creation response", "error", err)

		return nil, fmt.Errorf("failed to decode issue creation response: %w", err)
	}

	return &response.Issue, nil
}

func (c *Client) EditIssue(ctx context.Context, issueID int, issue *IssueEditOptions) error {
	// Marshal the issue struct to JSON
	bodyBytes, err := json.Marshal(IssueUpdateRequest{Issue: issue})
	if err != nil {
		slog.Error("Failed to marshal issue", "error", err)
		return fmt.Errorf("failed to marshal issue: %w", err)
	}
	// Log the last 100 characters of the body for debugging purposes
	slog.Debug("Editing issue", "issueID", issueID, "issue", string(bodyBytes)[max(0, len(string(bodyBytes))-100):])

	body := bytes.NewBuffer(bodyBytes)
	resp, err := c.redmineRequest(ctx, http.MethodPut, fmt.Sprintf("/issues/%s.json", strconv.Itoa(issueID)), nil, body)
	if err != nil {
		slog.Error("Failed to edit issue", "error", err)
		return fmt.Errorf("failed to edit issue: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		bodyContent, _ := io.ReadAll(resp.Body)
		slog.Error("Failed to edit issue", "status_code", resp.StatusCode, "response_body", string(bodyContent))
		return fmt.Errorf("failed to edit issue, status code: %d, response: %s", resp.StatusCode, string(bodyContent))
	}

	return nil
}

func (c *Client) FetchIssueTrackers(ctx context.Context) ([]*Tracker, error) {
	resp, err := c.redmineRequest(ctx, http.MethodGet, "/trackers.json", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch trackers: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch trackers, status code: %d", resp.StatusCode)
	}

	var response TrackersResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode trackers response: %w", err)
	}

	return response.Trackers, nil
}

func (c *Client) FetchIssueStatuses(ctx context.Context) ([]*Status, error) {
	resp, err := c.redmineRequest(ctx, http.MethodGet, "/issue_statuses.json", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issue statuses: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch issue statuses, status code: %d", resp.StatusCode)
	}

	var response StatusesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode issue statuses response: %w", err)
	}

	return response.Statuses, nil
}

func (c *Client) FetchIssuePriorities(ctx context.Context) ([]*Priority, error) {
	resp, err := c.redmineRequest(ctx, http.MethodGet, "/enumerations/issue_priorities.json", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch issue priorities: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch issue priorities, status code: %d", resp.StatusCode)
	}

	var response PrioritiesResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return nil, fmt.Errorf("failed to decode issue priorities response: %w", err)
	}

	return response.Priorities, nil
}

func (c *Client) redmineRequest(ctx context.Context, method string, url string, query map[string]string, body io.Reader) (*http.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	slog.Debug("Making Redmine request", "method", method, "url", req.URL.String(), "query", query, "key", c.AccessToken)
	req.Header.Set("X-Redmine-API-Key", c.AccessToken)

	return utils.EgressClient.Do(req)
}
