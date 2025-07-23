// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: 	AGPL-3.0-or-later

package webhook

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
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
		return nil, err
	}

	if c.Secret != nil {
		req.Header.Set("X-DevGuard-Token", *c.Secret)
	}

	req.Header.Set("Content-Type", "application/json")

	return http.DefaultClient.Do(req)
}

func (c *webhookClient) SendSBOM(SBOM cdx.BOM) error {
	var buf bytes.Buffer
	err := cdx.NewBOMEncoder(&buf, cdx.BOMFileFormatJSON).Encode(&SBOM)
	if err != nil {
		return err
	}

	resp, err := c.CreateRequest("POST", c.URL, &buf)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to send SBOM, status: %s, body: %s", resp.Status, body)
	}

	return nil
}
