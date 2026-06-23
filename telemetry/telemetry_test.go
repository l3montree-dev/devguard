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

package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

type failingClient struct{}

func (failingClient) Do(req *http.Request) (*http.Response, error) {
	return nil, errors.New("network unavailable")
}

type captureClient struct {
	body       []byte
	requests   int32
	statusCode int
	userAgent  string
}

func (c *captureClient) Do(req *http.Request) (*http.Response, error) {
	atomic.AddInt32(&c.requests, 1)
	c.userAgent = req.UserAgent()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	c.body = body

	statusCode := c.statusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}

	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader("")),
	}, nil
}

type fakeAPIStatsCollector struct {
	stats APIStats
	calls int32
}

func (f *fakeAPIStatsCollector) CollectAPIStartupStats(ctx context.Context) APIStats {
	atomic.AddInt32(&f.calls, 1)
	return f.stats
}

func TestAPIStartupPayload(t *testing.T) {
	event := APIStartupEvent("1.2.3", "https://app.example.org", "database.internal", "devguard_prod", APIStats{
		OrgCount:     int64Ptr(3),
		ProjectCount: int64Ptr(5),
		AssetCount:   int64Ptr(8),
	})

	payload := BuildStartupPayload(event)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	if payload.Type != "event" {
		t.Fatalf("expected event type, got %q", payload.Type)
	}
	if payload.Payload.Name != EventName {
		t.Fatalf("expected event name %q, got %q", EventName, payload.Payload.Name)
	}
	if payload.Payload.Website != WebsiteID {
		t.Fatalf("expected website id %q, got %q", WebsiteID, payload.Payload.Website)
	}
	if payload.Payload.Hostname != ComponentAPI {
		t.Fatalf("expected hostname %q, got %q", ComponentAPI, payload.Payload.Hostname)
	}
	if payload.Payload.Data["component"] != ComponentAPI {
		t.Fatalf("expected component %q, got %v", ComponentAPI, payload.Payload.Data["component"])
	}
	if payload.Payload.Data["version"] != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %v", payload.Payload.Data["version"])
	}
	if payload.Payload.Data["schemaVersion"] != SchemaVersion {
		t.Fatalf("expected schemaVersion %d, got %v", SchemaVersion, payload.Payload.Data["schemaVersion"])
	}
	if payload.Payload.Data["instanceId"] != payload.Payload.ID {
		t.Fatalf("expected instanceId data field %q, got %v", payload.Payload.ID, payload.Payload.Data["instanceId"])
	}
	if payload.Payload.Data["orgCount"] != int64(3) {
		t.Fatalf("expected orgCount 3, got %v", payload.Payload.Data["orgCount"])
	}
	if payload.Payload.Data["projectCount"] != int64(5) {
		t.Fatalf("expected projectCount 5, got %v", payload.Payload.Data["projectCount"])
	}
	if payload.Payload.Data["assetCount"] != int64(8) {
		t.Fatalf("expected assetCount 8, got %v", payload.Payload.Data["assetCount"])
	}
	if len(payload.Payload.ID) != instanceIDLength {
		t.Fatalf("expected truncated sha256 instance id, got %q", payload.Payload.ID)
	}

	for _, rawValue := range []string{"app.example.org", "database.internal", "devguard_prod"} {
		if strings.Contains(string(body), rawValue) {
			t.Fatalf("payload must not include raw instance input %q: %s", rawValue, string(body))
		}
	}
}

func TestScannerStartupPayloadDoesNotIncludeSensitiveRuntimeInputs(t *testing.T) {
	event := ScannerStartupEvent("2.0.0", "https://api.example.org/private/org/path?token=secret", "linux", "amd64", true, "sca ./private/repo/path")

	payload := BuildStartupPayload(event)
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	if payload.Payload.Hostname != ComponentScanner {
		t.Fatalf("expected hostname %q, got %q", ComponentScanner, payload.Payload.Hostname)
	}
	if payload.Payload.Data["component"] != ComponentScanner {
		t.Fatalf("expected component %q, got %v", ComponentScanner, payload.Payload.Data["component"])
	}
	if payload.Payload.Data["version"] != "2.0.0" {
		t.Fatalf("expected version 2.0.0, got %v", payload.Payload.Data["version"])
	}
	if payload.Payload.Data["schemaVersion"] != SchemaVersion {
		t.Fatalf("expected schemaVersion %d, got %v", SchemaVersion, payload.Payload.Data["schemaVersion"])
	}
	if payload.Payload.Data["instanceId"] != payload.Payload.ID {
		t.Fatalf("expected instanceId data field %q, got %v", payload.Payload.ID, payload.Payload.Data["instanceId"])
	}
	if payload.Payload.Data["os"] != "linux" {
		t.Fatalf("expected os linux, got %v", payload.Payload.Data["os"])
	}
	if payload.Payload.Data["arch"] != "amd64" {
		t.Fatalf("expected arch amd64, got %v", payload.Payload.Data["arch"])
	}
	if payload.Payload.Data["ci"] != true {
		t.Fatalf("expected ci true, got %v", payload.Payload.Data["ci"])
	}
	if payload.Payload.Data["command"] != "sca" {
		t.Fatalf("expected sanitized command sca, got %v", payload.Payload.Data["command"])
	}

	for _, rawValue := range []string{"private/org/path", "token=secret", "api.example.org", "private/repo/path"} {
		if strings.Contains(string(body), rawValue) {
			t.Fatalf("payload must not include raw scanner input %q: %s", rawValue, string(body))
		}
	}
}

func TestConfigFromEnvDisabledValues(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "1", "yes", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv(EnvDisabled, value)

			cfg := ConfigFromEnv()

			if !cfg.Disabled {
				t.Fatalf("expected %q to disable telemetry", value)
			}
		})
	}
}

func TestRuntimeVersionUsesBuildVersion(t *testing.T) {
	version := RuntimeVersion("v1.5.1-9-g434a075c-dirty")

	if version != "v1.5.1-9-g434a075c-dirty" {
		t.Fatalf("expected actual build version, got %q", version)
	}
}

func TestRuntimeVersionSkipsEmptyAndDevelPlaceholders(t *testing.T) {
	version := RuntimeVersion("", "  ", "(devel)", "v1.5.1")

	if version != "v1.5.1" {
		t.Fatalf("expected first real build version, got %q", version)
	}
}

func TestSendStartupWarnsButDoesNotFailForRejectedRequest(t *testing.T) {
	client := &captureClient{statusCode: http.StatusInternalServerError}

	SendStartup(context.Background(), Config{}, client, ScannerStartupEvent("1.0.0", "https://api.example.org", "linux", "amd64", false, "version"))

	if client.requests != 1 {
		t.Fatalf("expected one request, got %d", client.requests)
	}
}

func TestSendStartupUsesTrackerCompatibleUserAgent(t *testing.T) {
	client := &captureClient{}

	SendStartup(context.Background(), Config{}, client, ScannerStartupEvent("1.0.0", "https://api.example.org", "linux", "amd64", false, "version"))

	if client.userAgent != UserAgent {
		t.Fatalf("expected tracker-compatible user agent, got %q", client.userAgent)
	}
}

func TestSendStartupLogsTransparencyNotice(t *testing.T) {
	var logOutput bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logOutput, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previousLogger)
	})

	SendStartup(context.Background(), Config{}, &captureClient{}, ScannerStartupEvent("1.0.0", "https://api.example.org", "linux", "amd64", false, "version"))

	logs := logOutput.String()
	if !strings.Contains(logs, TransparencyLog) {
		t.Fatalf("expected transparency log %q, got %s", TransparencyLog, logs)
	}
	if !strings.Contains(logs, EnvDisabled) {
		t.Fatalf("expected opt-out env %q in logs, got %s", EnvDisabled, logs)
	}
	if !strings.Contains(logs, "payload_data") {
		t.Fatalf("expected logged telemetry payload data, got %s", logs)
	}
}

func TestSendStartupWarnsButDoesNotFailForRequestError(t *testing.T) {
	SendStartup(context.Background(), Config{}, failingClient{}, ScannerStartupEvent("1.0.0", "https://api.example.org", "linux", "amd64", false, "version"))
}

func TestSendAPIStartupIncludesCountsFromCollector(t *testing.T) {
	var requestBody umamiRequest
	client := &captureClient{}

	collector := &fakeAPIStatsCollector{
		stats: APIStats{
			OrgCount:     int64Ptr(2),
			ProjectCount: int64Ptr(4),
			AssetCount:   int64Ptr(9),
		},
	}

	t.Setenv("FRONTEND_URL", "https://app.example.org")
	t.Setenv("POSTGRES_HOST", "database.internal")
	t.Setenv("POSTGRES_DB", "devguard_prod")

	SendAPIStartup(context.Background(), Config{}, client, collector, "1.2.3")

	if err := json.Unmarshal(client.body, &requestBody); err != nil {
		t.Fatal(err)
	}

	if requestBody.Payload.Data["component"] != ComponentAPI {
		t.Fatalf("expected component %q, got %v", ComponentAPI, requestBody.Payload.Data["component"])
	}
	if requestBody.Payload.Data["version"] != "1.2.3" {
		t.Fatalf("expected version 1.2.3, got %v", requestBody.Payload.Data["version"])
	}
	if requestBody.Payload.Data["orgCount"] != float64(2) {
		t.Fatalf("expected orgCount 2, got %v", requestBody.Payload.Data["orgCount"])
	}
	if requestBody.Payload.Data["projectCount"] != float64(4) {
		t.Fatalf("expected projectCount 4, got %v", requestBody.Payload.Data["projectCount"])
	}
	if requestBody.Payload.Data["assetCount"] != float64(9) {
		t.Fatalf("expected assetCount 9, got %v", requestBody.Payload.Data["assetCount"])
	}
	if requestBody.Payload.Data["schemaVersion"] != float64(SchemaVersion) {
		t.Fatalf("expected schemaVersion %d, got %v", SchemaVersion, requestBody.Payload.Data["schemaVersion"])
	}
	if requestBody.Payload.Data["instanceId"] != requestBody.Payload.ID {
		t.Fatalf("expected instanceId data field %q, got %v", requestBody.Payload.ID, requestBody.Payload.Data["instanceId"])
	}
	if atomic.LoadInt32(&collector.calls) != 1 {
		t.Fatalf("expected collector to be called once, got %d", collector.calls)
	}
}

func TestSendAPIStartupSkipsCollectionWhenDisabled(t *testing.T) {
	collector := &fakeAPIStatsCollector{}

	SendAPIStartup(context.Background(), Config{Disabled: true}, nil, collector, "1.2.3")

	if atomic.LoadInt32(&collector.calls) != 0 {
		t.Fatalf("expected collector not to be called when disabled, got %d", collector.calls)
	}
}

func int64Ptr(value int64) *int64 {
	return &value
}
