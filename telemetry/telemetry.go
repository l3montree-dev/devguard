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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
)

const (
	ComponentAPI     = "devguard-api"
	ComponentScanner = "devguard-scanner"

	EventName       = "devguard-instance-start"
	DefaultEndpoint = "https://umami.l3montree.com/api/send"
	WebsiteID       = "2ab9fe36-42ec-485d-a592-b0f6e78dd1ad"
	DefaultTimeout  = 3 * time.Second
	UserAgent       = "DevguardTelemetry"
	SchemaVersion   = 1
	TransparencyLog = "sending anonymized telemetry data - nothing personal or critical is included. " +
		"This helps us understand what DevGuard versions are used and which versions we should provide patches for. " +
		"You can disable this by setting DEVGUARD_TELEMETRY_DISABLED=true."

	EnvDisabled = "DEVGUARD_TELEMETRY_DISABLED"

	// Umami stores the distinct/session id in varchar(50). Keep a stable
	// SHA-256-derived id, but short enough for Umami's schema.
	instanceIDLength = 32
)

type Config struct {
	Disabled bool
}

type StartupEvent struct {
	Component  string
	Version    string
	InstanceID string
	Data       map[string]any
}

type APIStats struct {
	OrgCount     *int64
	ProjectCount *int64
	AssetCount   *int64
}

type APIStatsCollector interface {
	CollectAPIStartupStats(ctx context.Context) APIStats
}

type GormAPIStatsCollector struct {
	db shared.DB
}

type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

type umamiRequest struct {
	Payload umamiPayload `json:"payload"`
	Type    string       `json:"type"`
}

type umamiPayload struct {
	Hostname string         `json:"hostname"`
	URL      string         `json:"url"`
	Title    string         `json:"title"`
	Website  string         `json:"website"`
	Name     string         `json:"name"`
	ID       string         `json:"id"`
	Data     map[string]any `json:"data"`
}

func ConfigFromEnv() Config {
	return Config{
		Disabled: isTruthyEnv(os.Getenv(EnvDisabled)),
	}
}

func NewGormAPIStatsCollector(db shared.DB) GormAPIStatsCollector {
	return GormAPIStatsCollector{db: db}
}

func (c GormAPIStatsCollector) CollectAPIStartupStats(ctx context.Context) APIStats {
	return APIStats{
		OrgCount:     c.count(ctx, "organization", &models.Org{}),
		ProjectCount: c.count(ctx, "project", &models.Project{}),
		AssetCount:   c.count(ctx, "asset", &models.Asset{}),
	}
}

func (c GormAPIStatsCollector) count(ctx context.Context, label string, model any) *int64 {
	if c.db == nil {
		slog.Warn("could not collect DevGuard startup telemetry count because database is unavailable", "count", label)
		return nil
	}

	var count int64
	if err := c.db.WithContext(ctx).Model(model).Count(&count).Error; err != nil {
		slog.Warn("could not collect DevGuard startup telemetry count", "count", label, "err", err)
		return nil
	}
	return &count
}

func APIStartupEvent(version, frontendURL, postgresHost, postgresDB string, stats APIStats) StartupEvent {
	data := map[string]any{
		"component": ComponentAPI,
		"version":   version,
	}
	addOptionalCount(data, "orgCount", stats.OrgCount)
	addOptionalCount(data, "projectCount", stats.ProjectCount)
	addOptionalCount(data, "assetCount", stats.AssetCount)

	return StartupEvent{
		Component:  ComponentAPI,
		Version:    version,
		InstanceID: HashParts(ComponentAPI, frontendURL, postgresHost, postgresDB),
		Data:       data,
	}
}

func ScannerStartupEvent(version, apiURL, goos, goarch string, runsInCI bool, command string) StartupEvent {
	apiHost := hostFromURL(apiURL)
	data := map[string]any{
		"component": ComponentScanner,
		"version":   version,
		"os":        goos,
		"arch":      goarch,
		"ci":        runsInCI,
		"command":   normalizeCommandName(command),
	}

	return StartupEvent{
		Component:  ComponentScanner,
		Version:    version,
		InstanceID: HashParts(ComponentScanner, apiHost, goos, goarch),
		Data:       data,
	}
}

func SendAPIStartup(ctx context.Context, cfg Config, client HTTPDoer, statsCollector APIStatsCollector, version string) {
	if cfg.Disabled {
		SendStartup(ctx, cfg, client, APIStartupEvent(
			version,
			os.Getenv("FRONTEND_URL"),
			os.Getenv("POSTGRES_HOST"),
			os.Getenv("POSTGRES_DB"),
			APIStats{},
		))
		return
	}

	var stats APIStats
	if statsCollector == nil {
		slog.Warn("could not collect DevGuard API startup telemetry stats because no collector is configured")
	} else {
		stats = statsCollector.CollectAPIStartupStats(ctx)
	}

	SendStartup(ctx, cfg, client, APIStartupEvent(
		version,
		os.Getenv("FRONTEND_URL"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_DB"),
		stats,
	))
}

func SendScannerStartup(ctx context.Context, cfg Config, client HTTPDoer, version, apiURL string, runsInCI bool, command string) {
	SendStartup(ctx, cfg, client, ScannerStartupEvent(version, apiURL, runtime.GOOS, runtime.GOARCH, runsInCI, command))
}

func SendStartup(ctx context.Context, cfg Config, client HTTPDoer, event StartupEvent) {
	if cfg.Disabled {
		slog.Info("DevGuard startup telemetry is disabled", "env", EnvDisabled, "component", event.Component)
		return
	}

	if client == nil {
		client = http.DefaultClient
	}

	requestPayload := BuildStartupPayload(event)
	body, err := json.Marshal(requestPayload)
	if err != nil {
		slog.Warn("could not encode DevGuard startup telemetry payload", "err", err, "component", event.Component)
		return
	}

	logFields := []any{
		"component", event.Component,
		"version", event.Version,
		"instance_id", event.InstanceID,
		"payload_data", requestPayload.Payload.Data,
		"disable_env", EnvDisabled,
	}
	slog.Info(TransparencyLog, logFields...)

	sendCtx, cancel := context.WithTimeout(ctx, DefaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(sendCtx, http.MethodPost, DefaultEndpoint, bytes.NewReader(body))
	if err != nil {
		slog.Warn("could not create DevGuard startup telemetry request", "err", err, "component", event.Component)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("DevGuard startup telemetry failed", "err", err, "component", event.Component)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		slog.Warn("DevGuard startup telemetry was not accepted by Umami", "status", resp.StatusCode, "component", event.Component)
	}
}

func BuildStartupPayload(event StartupEvent) umamiRequest {
	data := map[string]any{}
	for key, value := range event.Data {
		data[key] = value
	}
	data["component"] = event.Component
	data["version"] = event.Version
	data["schemaVersion"] = SchemaVersion
	data["instanceId"] = event.InstanceID

	return umamiRequest{
		Type: "event",
		Payload: umamiPayload{
			Hostname: event.Component,
			URL:      "/startup",
			Title:    "DevGuard startup",
			Website:  WebsiteID,
			Name:     EventName,
			ID:       event.InstanceID,
			Data:     data,
		},
	}
}

func addOptionalCount(data map[string]any, key string, value *int64) {
	if value != nil {
		data[key] = *value
	}
}

func HashParts(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write([]byte(strings.TrimSpace(strings.ToLower(part))))
		hash.Write([]byte{0})
	}
	return hex.EncodeToString(hash.Sum(nil))[:instanceIDLength]
}

func isTruthyEnv(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func RuntimeVersion(values ...string) string {
	for _, value := range values {
		if version := normalizeBuildVersion(value); version != "" {
			return version
		}
	}

	if info, ok := debug.ReadBuildInfo(); ok {
		if version := normalizeBuildVersion(info.Main.Version); version != "" {
			return version
		}
	}

	return "dev"
}

func normalizeBuildVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" || version == "(devel)" {
		return ""
	}
	return version
}

func normalizeCommandName(command string) string {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return "unknown"
	}
	if fields[0] == "devguard-scanner" && len(fields) > 1 {
		return fields[1]
	}
	return fields[0]
}

func hostFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return ""
	}

	parseURL := rawURL
	if !strings.Contains(parseURL, "://") {
		parseURL = "https://" + parseURL
	}

	parsed, err := url.Parse(parseURL)
	if err != nil || parsed.Host == "" {
		return strings.ToLower(rawURL)
	}
	return strings.ToLower(parsed.Host)
}
