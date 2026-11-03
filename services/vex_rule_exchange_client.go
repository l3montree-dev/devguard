// Copyright (C) 2026 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package services

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
)

type vexRuleExchangeClient struct {
	baseURL    string
	privateKey string
	publicKey  string
	client     *http.Client
}

// vexExchangeURL is the central VEX exchange server all instances share.
var vexExchangeURL = "http://localhost:8082"

func NewVEXRuleExchangeClient() *vexRuleExchangeClient {
	baseURL := strings.TrimSuffix(vexExchangeURL, "/")
	privateKeyPath := os.Getenv("INSTANCE_ADMIN_PRIVATE_KEY_PATH")
	publicKeyPath := os.Getenv("INSTANCE_ADMIN_PUB_KEY_PATH")
	if privateKeyPath == "" || publicKeyPath == "" {
		slog.Info("no instance admin key pair configured, the exchange of VEX rules is disabled")
		return &vexRuleExchangeClient{}
	}

	privateKeyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		slog.Error("could not read instance admin private key — the exchange of VEX rules is disabled", "err", err)
		return &vexRuleExchangeClient{}
	}
	publicKeyBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		slog.Error("could not read instance admin public key — the exchange of VEX rules is disabled", "err", err)
		return &vexRuleExchangeClient{}
	}

	client, err := newVEXRuleExchangeClient(baseURL, strings.TrimSpace(string(privateKeyBytes)))
	if err != nil {
		slog.Error("could not parse instance admin private key — the exchange of VEX rules is disabled", "err", err)
		return &vexRuleExchangeClient{}
	}
	// TrimSpace so that trailing newlines from editors do not corrupt the comparison
	if !strings.EqualFold(client.publicKey, strings.TrimSpace(string(publicKeyBytes))) {
		slog.Error("instance admin private key does not belong to the instance admin public key — the exchange of VEX rules is disabled")
		return &vexRuleExchangeClient{}
	}
	return client
}

func newVEXRuleExchangeClient(baseURL, hexPrivateKey string) (*vexRuleExchangeClient, error) {
	_, publicKey, err := HexTokenToECDSA(hexPrivateKey)
	if err != nil {
		return nil, err
	}
	publicKeyBytes, err := GetPubKeyBytes(publicKey)
	if err != nil {
		return nil, err
	}
	return &vexRuleExchangeClient{
		baseURL:    baseURL,
		privateKey: hexPrivateKey,
		publicKey:  hex.EncodeToString(publicKeyBytes),
		client:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

var _ shared.VEXRuleExchangeClient = (*vexRuleExchangeClient)(nil)

func (c *vexRuleExchangeClient) Enabled() bool {
	return c.baseURL != "" && c.privateKey != ""
}

// Register is idempotent on the server, a known key is registered again without changes.
func (c *vexRuleExchangeClient) Register(ctx context.Context) error {
	return c.do(ctx, http.MethodPost, "/instances/register", map[string]string{
		"publicKey": c.publicKey,
	}, nil, http.StatusCreated)
}

func (c *vexRuleExchangeClient) SubmitVEXRules(ctx context.Context, rules []dtos.VEXExchangeRuleDTO) error {
	if rules == nil {
		rules = []dtos.VEXExchangeRuleDTO{}
	}
	return c.do(ctx, http.MethodPost, "/vex-rules", dtos.VEXExchangeSubmitRequest{Rules: rules}, nil, http.StatusNoContent)
}

func (c *vexRuleExchangeClient) FetchRecommendations(ctx context.Context) ([]dtos.VEXExchangeRecommendationDTO, error) {
	var recommendations []dtos.VEXExchangeRecommendationDTO
	if err := c.do(ctx, http.MethodGet, "/recommendations", nil, &recommendations, http.StatusOK); err != nil {
		return nil, err
	}
	return recommendations, nil
}

func (c *vexRuleExchangeClient) do(ctx context.Context, method, path string, body any, response any, expectedStatus int) error {
	if !c.Enabled() {
		return fmt.Errorf("VEX rule exchange client is not enabled")
	}

	var bodyReader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("could not encode request body: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("could not create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if err := signRequest(c.privateKey, req); err != nil {
		return fmt.Errorf("could not sign request: %w", err)
	}

	res, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("could not send request to VEX exchange server: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != expectedStatus {
		message, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
		return fmt.Errorf("unexpected response from VEX exchange server for %s %s: %s %s", method, path, res.Status, strings.TrimSpace(string(message)))
	}

	if response == nil {
		return nil
	}
	if err := json.NewDecoder(res.Body).Decode(response); err != nil {
		return fmt.Errorf("could not decode response of VEX exchange server: %w", err)
	}
	return nil
}
