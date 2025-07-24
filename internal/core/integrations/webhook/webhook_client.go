// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
)

type WebhookStruct struct {
	Organization core.OrgObject          `json:"organization"`
	Project      core.ProjectObject      `json:"project"`
	Asset        core.AssetObject        `json:"asset"`
	AssetVersion core.AssetVersionObject `json:"assetVersion"`
	Payload      any                     `json:"payload"`
	Type         WebhookType             `json:"type"`
}

type WebhookType string

const (
	WebhookTypeSBOM                      WebhookType = "sbom"
	WebhookTypeFirstPartyVulnerabilities WebhookType = "firstPartyVulnerabilities"
	WebhookTypeDependencyVulnerabilities WebhookType = "dependencyVulnerabilities"
)

type webhookClient struct {
	URL    string
	Secret *string
}

func NewWebhookClient(url string, secret *string) *webhookClient {
	return &webhookClient{
		URL:    url,
		Secret: secret,
	}
}

func (c *webhookClient) CreateRequest(method, url string, body io.Reader) (*http.Response, error) {

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return nil, err
	}

	if c.Secret != nil {
		req.Header.Set("X-DevGuard-Token", *c.Secret)
	}

	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

func (c *webhookClient) SendSBOM(SBOM cdx.BOM, org core.OrgObject, project core.ProjectObject, asset core.AssetObject, assetVersion core.AssetVersionObject) error {

	body := WebhookStruct{
		Organization: org,
		Project:      project,
		Asset:        asset,
		AssetVersion: assetVersion,
		Payload:      SBOM,
		Type:         WebhookTypeSBOM,
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(body)
	if err != nil {
		return err
	}

	resp, err := c.CreateRequest("POST", c.URL, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send SBOM, status: %s", resp.Status)
	}

	return nil
}

func (c *webhookClient) SendFirstPartyVulnerabilities(vuln []vuln.FirstPartyVulnDTO, org core.OrgObject, project core.ProjectObject, asset core.AssetObject, assetVersion core.AssetVersionObject) error {

	body := WebhookStruct{
		Organization: org,
		Project:      project,
		Asset:        asset,
		AssetVersion: assetVersion,
		Payload:      vuln,
		Type:         WebhookTypeFirstPartyVulnerabilities,
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(body)
	if err != nil {
		return err
	}

	resp, err := c.CreateRequest("POST", c.URL, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send vulnerability, status: %s,", resp.Status)
	}

	return nil
}

func (c *webhookClient) SendDependencyVulnerabilities(vuln []vuln.DependencyVulnDTO, org core.OrgObject, project core.ProjectObject, asset core.AssetObject, assetVersion core.AssetVersionObject) error {

	body := WebhookStruct{
		Organization: org,
		Project:      project,
		Asset:        asset,
		AssetVersion: assetVersion,
		Payload:      vuln,
		Type:         WebhookTypeDependencyVulnerabilities,
	}

	var buf bytes.Buffer
	err := json.NewEncoder(&buf).Encode(body)
	if err != nil {
		return err
	}

	resp, err := c.CreateRequest("POST", c.URL, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send vulnerability, status: %s", resp.Status)
	}

	return nil
}
