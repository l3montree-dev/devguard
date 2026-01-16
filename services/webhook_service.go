// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/transformer"
)

type WebhookStruct struct {
	Organization shared.OrgObject          `json:"organization"`
	Project      shared.ProjectObject      `json:"project"`
	Asset        shared.AssetObject        `json:"asset"`
	AssetVersion shared.AssetVersionObject `json:"assetVersion"`
	Payload      any                       `json:"payload"`
	Type         WebhookType               `json:"type"`
	Artifact     shared.ArtifactObject     `json:"artifact,omitempty"`
}

type WebhookType string

const (
	WebhookTypeSBOM                      WebhookType = "sbom"
	WebhookTypeFirstPartyVulnerabilities WebhookType = "firstPartyVulnerabilities"
	WebhookTypeDependencyVulnerabilities WebhookType = "dependencyVulnerabilities"
	WebhookTypeTest                      WebhookType = "test"
)

type TestPayloadType string

const (
	TestPayloadTypeEmpty                 TestPayloadType = "empty"
	TestPayloadTypeSampleSBOM            TestPayloadType = "sampleSbom"
	TestPayloadTypeSampleDependencyVulns TestPayloadType = "sampleDependencyVulns"
	TestPayloadTypeSampleFirstPartyVulns TestPayloadType = "sampleFirstPartyVulns"
)

type webhookClient struct {
	URL    string
	Secret *string
}

func NewWebhookService(url string, secret *string) *webhookClient {
	return &webhookClient{
		URL:    url,
		Secret: secret,
	}
}

func (c *webhookClient) CreateRequest(method, url string, body io.Reader) (*http.Response, error) {
	bodyBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("failed to read request body: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// Retry logic with delays: 1s, 5s, 10s
	retryDelays := []time.Duration{1 * time.Second, 5 * time.Second, 10 * time.Second}

	var resp *http.Response

	for i, delay := range retryDelays {
		req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}

		if c.Secret != nil {
			req.Header.Set("X-Webhook-Secret", *c.Secret)
		}

		req.Header.Set("Content-Type", "application/json")

		resp, err = http.DefaultClient.Do(req)

		if err == nil && resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return resp, nil
		}

		if i == len(retryDelays)-1 {
			return nil, fmt.Errorf("webhook request failed with no response")
		}

		time.Sleep(delay)
	}

	// This should never be reached due to the break condition above
	return nil, fmt.Errorf("unexpected end of retry loop")

}

func (c *webhookClient) SendSBOM(SBOM cdx.BOM, org shared.OrgObject, project shared.ProjectObject, asset shared.AssetObject, assetVersion shared.AssetVersionObject, artifact shared.ArtifactObject) error {

	body := WebhookStruct{
		Organization: org,
		Project:      project,
		Asset:        asset,
		AssetVersion: assetVersion,
		Payload:      SBOM,
		Type:         WebhookTypeSBOM,
		Artifact:     artifact,
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
	if resp == nil {
		return fmt.Errorf("received nil response when sending SBOM")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to send SBOM, status: %s", resp.Status)
	}

	return nil
}

func (c *webhookClient) SendFirstPartyVulnerabilities(vuln []dtos.FirstPartyVulnDTO, org shared.OrgObject, project shared.ProjectObject, asset shared.AssetObject, assetVersion shared.AssetVersionObject) error {
	return nil

	/*body := WebhookStruct{
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

	return nil*/
}

func (c *webhookClient) SendDependencyVulnerabilities(vuln []dtos.DependencyVulnDTO, org shared.OrgObject, project shared.ProjectObject, asset shared.AssetObject, assetVersion shared.AssetVersionObject, artifact shared.ArtifactObject) error {

	body := WebhookStruct{
		Organization: org,
		Project:      project,
		Asset:        asset,
		AssetVersion: assetVersion,
		Payload:      vuln,
		Artifact:     artifact,
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
	if resp == nil {
		return fmt.Errorf("received nil response when sending dependency vulnerabilities")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to send vulnerability, status: %s", resp.Status)
	}

	return nil
}

func (c *webhookClient) SendTest(org shared.OrgObject, project shared.ProjectObject, asset shared.AssetObject, assetVersion shared.AssetVersionObject, payloadType TestPayloadType) error {

	var payload any
	var webhookType WebhookType

	switch payloadType {
	case TestPayloadTypeEmpty:
		payload = map[string]any{
			"message":   "This is a test webhook from DevGuard",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		webhookType = WebhookTypeTest

	case TestPayloadTypeSampleSBOM:
		payload = createSampleSBOM()
		webhookType = WebhookTypeSBOM

	case TestPayloadTypeSampleDependencyVulns:
		payload = createSampleDependencyVulns()
		webhookType = WebhookTypeDependencyVulnerabilities

	case TestPayloadTypeSampleFirstPartyVulns:
		payload = createSampleFirstPartyVulns()
		webhookType = WebhookTypeFirstPartyVulnerabilities

	default:
		payload = map[string]any{
			"message":   "This is a test webhook from DevGuard",
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		webhookType = WebhookTypeTest
	}

	body := WebhookStruct{
		Organization: org,
		Project:      project,
		Asset:        asset,
		AssetVersion: assetVersion,
		Payload:      payload,
		Type:         webhookType,
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
	if resp == nil {
		return fmt.Errorf("received nil response when sending test webhook")
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil // Success
	}

	return fmt.Errorf("failed to send test webhook, status: %s", resp.Status)
}

func createSampleSBOM() cdx.BOM {
	return cdx.BOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  cdx.SpecVersion1_4,
		SerialNumber: "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
		Version:      1,
		Metadata: &cdx.Metadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Component: &cdx.Component{
				Type:       cdx.ComponentTypeApplication,
				Name:       "example-web-app",
				Version:    "1.2.3",
				PackageURL: "pkg:docker/example/web-app@1.2.3",
			},
		},
		Components: &[]cdx.Component{
			{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "express",
				Version:    "4.18.2",
				PackageURL: "pkg:npm/express@4.18.2",
				Licenses: &cdx.Licenses{
					{License: &cdx.License{ID: "MIT"}},
				},
			},
			{
				Type:       cdx.ComponentTypeLibrary,
				Name:       "log4j-core",
				Version:    "2.14.1",
				PackageURL: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
				Licenses: &cdx.Licenses{
					{License: &cdx.License{ID: "Apache-2.0"}},
				},
			},
		},
	}
}

func createSampleDependencyVulns() []dtos.DependencyVulnDTO {
	cve := "CVE-2021-44228"
	purl := "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
	fixedVersion := "2.15.0"
	depth := 2
	risk := 95
	rawRisk := 9.8
	priority := 1
	effort := 4

	cveData := models.CVE{
		CVE:         "CVE-2021-44228",
		Description: "Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
		CVSS:        10.0,
		Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
	}

	return []dtos.DependencyVulnDTO{
		{
			ID: "dep-vuln-001",
			//	ScannerIDs:            "trivy",
			AssetVersionName:      "v1.2.3",
			AssetID:               "asset-12345",
			State:                 dtos.VulnStateOpen,
			CVEID:                 cve,
			CVE:                   transformer.CVEToDTO(cveData),
			ComponentPurl:         purl,
			ComponentDepth:        &depth,
			ComponentFixedVersion: &fixedVersion,
			Effort:                &effort,
			RiskAssessment:        &risk,
			RawRiskAssessment:     &rawRisk,
			Priority:              &priority,
			LastDetected:          time.Now(),
			CreatedAt:             time.Now().Add(-24 * time.Hour),
			RiskRecalculatedAt:    time.Now(),
		},
	}
}

func createSampleFirstPartyVulns() []dtos.FirstPartyVulnDTO {
	message := "SQL injection vulnerability detected"

	return []dtos.FirstPartyVulnDTO{
		{
			ID:               "fpv-001",
			ScannerIDs:       "semgrep",
			Message:          &message,
			AssetVersionName: "v1.2.3",
			AssetID:          "asset-12345",
			State:            dtos.VulnStateOpen,
			RuleID:           "javascript.lang.security.audit.sqli",
			URI:              "src/auth/login.js",
			SnippetContents: []dtos.SnippetContent{
				{
					StartLine: 42,
					EndLine:   45,
					Snippet:   `const query = "SELECT * FROM users WHERE username = '" + username + "'";`,
				},
			},
			CreatedAt:       time.Now(),
			Commit:          "abc123",
			Author:          "Developer",
			RuleName:        "SQL Injection Detection",
			RuleDescription: "Detects SQL injection vulnerabilities",
			RuleProperties: map[string]any{
				"severity": "HIGH",
				"cwe":      "CWE-89",
			},
		},
	}
}
