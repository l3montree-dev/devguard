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

package controllers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/monitoring"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
)

// daemonCooldown is the minimum interval between two manual triggers of the same daemon.
const daemonCooldown = 5 * time.Minute

type daemonTriggerTimestamp struct {
	Time time.Time `json:"time"`
}

type AdminController struct {
	daemonRunner        shared.DaemonRunner
	vulnDBImportService shared.VulnDBImportService
	configService       shared.ConfigService
}

func NewAdminController(
	daemonRunner shared.DaemonRunner,
	vulnDBImportService shared.VulnDBImportService,
	configService shared.ConfigService,
) *AdminController {
	return &AdminController{
		daemonRunner:        daemonRunner,
		vulnDBImportService: vulnDBImportService,
		configService:       configService,
	}
}

// checkCooldown reads the config DB for the last trigger time and returns an
// error message if the cooldown has not elapsed yet.
// Because the timestamp lives in the shared config DB table, this correctly
// prevents duplicate triggers across multiple API instances.
func (c *AdminController) checkCooldown(configKey string) (ok bool, retryAfter time.Duration) {
	var ts daemonTriggerTimestamp
	err := c.configService.GetJSONConfig(configKey, &ts)
	if err != nil {
		// No record yet → ok to proceed
		return true, 0
	}
	elapsed := time.Since(ts.Time)
	if elapsed < daemonCooldown {
		return false, daemonCooldown - elapsed
	}
	return true, 0
}

// markTriggered writes the current timestamp to the config DB so that other
// instances (and subsequent requests) respect the cooldown.
// It reuses the same key that the automatic daemon scheduler checks via
// shouldMirror / markMirrored, so a manual trigger also resets the automatic
// 12-hour timer.
func (c *AdminController) markTriggered(configKey string) {
	if err := c.configService.SetJSONConfig(configKey, daemonTriggerTimestamp{Time: time.Now()}); err != nil {
		slog.Error("admin: failed to mark daemon triggered in config DB",
			"key", configKey, "err", err)
	}
}

// sseWriter wraps an http.ResponseWriter for Server-Sent Events.
type sseWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func newSSEWriter(w http.ResponseWriter) *sseWriter {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // nginx
	w.WriteHeader(http.StatusOK)

	var flusher http.Flusher
	if f, ok := w.(http.Flusher); ok {
		flusher = f
	}
	return &sseWriter{w: w, flusher: flusher}
}

func (s *sseWriter) sendEvent(event, data string) {
	// (SSE frames are delimited by \n\n).
	safeData := strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ").Replace(data)
	fmt.Fprintf(s.w, "event: %s\ndata: %s\n\n", event, safeData)
	if s.flusher != nil {
		s.flusher.Flush()
	}
}

func (s *sseWriter) sendLog(msg string) {
	s.sendEvent("log", msg)
}

func (s *sseWriter) sendDone() {
	s.sendEvent("done", `{"status":"completed"}`)
}

func (s *sseWriter) sendError(msg string) {
	// json.Marshal produces spec-compliant JSON, unlike %q which emits
	// Go-syntax escape sequences (\a, \v, \f) that are invalid in JSON.
	b, err := json.Marshal(map[string]string{"message": msg})
	if err != nil {
		// Fallback: send a static payload so the SSE stream still terminates cleanly.
		s.sendEvent("error", `{"message":"internal error"}`)
		return
	}
	s.sendEvent("error", string(b))
}

// TriggerOpenSourceInsights runs the open-source-insights daemon.
//
// @Summary Trigger the Open Source Insights daemon
// @Description Syncs open-source project metadata from deps.dev. Returns an SSE stream with log, done, and error events. Subject to a 5-minute cooldown (enforced across all API instances via the config DB).
// @Tags Admin Daemons
// @Security AdminSignedAuth
// @Produce text/event-stream
// @Success 200 {string} string "SSE stream (event: log | done | error)"
// @Failure 429 {object} echo.HTTPError "Cooldown not elapsed – try again later"
// @Router /admin/daemons/open-source-insights/trigger [post]
func (c *AdminController) TriggerOpenSourceInsights(ctx shared.Context) error {
	return c.runDaemonSSE(ctx, "vulndb.opensourceinsights", "Open Source Insights", func(sse *sseWriter) error {
		return c.daemonRunner.UpdateOpenSourceInsightInformation()
	})
}

// TriggerVulnDB runs the VulnDB import daemon.
//
// @Summary Trigger the VulnDB import daemon
// @Description Runs an incremental VulnDB import from upstream diffs. Sets the vulndb.vulndb config timestamp at the start of processing. Returns an SSE stream with log, done, and error events. Subject to a 5-minute cooldown.
// @Tags Admin Daemons
// @Security AdminSignedAuth
// @Produce text/event-stream
// @Success 200 {string} string "SSE stream (event: log | done | error)"
// @Failure 429 {object} echo.HTTPError "Cooldown not elapsed – try again later"
// @Router /admin/daemons/vulndb/trigger [post]
func (c *AdminController) TriggerVulnDB(ctx shared.Context) error {
	// The vulndb.vulndb timestamp is already set by markTriggered in
	// runDaemonSSE (before the handler runs), so no extra write needed here.
	return c.runDaemonSSE(ctx, "vulndb.vulndb", "VulnDB Import", func(sse *sseWriter) error {
		sse.sendLog("Running VulnDB import…")
		return c.daemonRunner.UpdateVulnDB()
	})
}

// TriggerVulnDBCleanup removes orphaned tables from failed VulnDB imports.
//
// @Summary Trigger VulnDB cleanup
// @Description Removes orphaned database tables left over from failed VulnDB imports. Returns an SSE stream with log, done, and error events. Subject to a 5-minute cooldown.
// @Tags Admin Daemons
// @Security AdminSignedAuth
// @Produce text/event-stream
// @Success 200 {string} string "SSE stream (event: log | done | error)"
// @Failure 429 {object} echo.HTTPError "Cooldown not elapsed – try again later"
// @Router /admin/daemons/vulndb-cleanup/trigger [post]
func (c *AdminController) TriggerVulnDBCleanup(ctx shared.Context) error {
	return c.runDaemonSSE(ctx, "daemon.vulndbCleanup", "VulnDB Cleanup", func(sse *sseWriter) error {
		return c.vulnDBImportService.CleanupOrphanedTables()
	})
}

// TriggerFixedVersions runs the fixed-versions daemon.
//
// @Summary Trigger the Fixed Versions daemon
// @Description Updates known fixed versions for tracked vulnerabilities. Returns an SSE stream with log, done, and error events. Subject to a 5-minute cooldown.
// @Tags Admin Daemons
// @Security AdminSignedAuth
// @Produce text/event-stream
// @Success 200 {string} string "SSE stream (event: log | done | error)"
// @Failure 429 {object} echo.HTTPError "Cooldown not elapsed – try again later"
// @Router /admin/daemons/fixed-versions/trigger [post]
func (c *AdminController) TriggerFixedVersions(ctx shared.Context) error {
	return c.runDaemonSSE(ctx, "vulndb.fixedVersions", "Fixed Versions", func(sse *sseWriter) error {
		return c.daemonRunner.UpdateFixedVersions()
	})
}

// TriggerAssetPipelineAll runs the asset pipeline for every asset.
//
// @Summary Trigger the asset pipeline for all assets
// @Description Runs the full asset pipeline (scan, sync, risk calculation, statistics) for every asset on this instance. Returns an SSE stream with log, done, and error events. Subject to a 5-minute cooldown.
// @Tags Admin Daemons
// @Security AdminSignedAuth
// @Produce text/event-stream
// @Success 200 {string} string "SSE stream (event: log | done | error)"
// @Failure 429 {object} echo.HTTPError "Cooldown not elapsed – try again later"
// @Router /admin/daemons/asset-pipeline-all/trigger [post]
func (c *AdminController) TriggerAssetPipelineAll(ctx shared.Context) error {
	return c.runDaemonSSE(ctx, "daemon.assetPipelineAll", "Asset Pipeline (all)", func(sse *sseWriter) error {
		c.daemonRunner.RunAssetPipeline(true)
		return nil
	})
}

// TriggerAssetPipelineSingle runs the asset pipeline for a single asset.
//
// @Summary Trigger the asset pipeline for a single asset
// @Description Runs the full asset pipeline for one asset identified by its UUID. Returns an SSE stream with log, done, and error events. Subject to a 5-minute cooldown per asset.
// @Tags Admin Daemons
// @Security AdminSignedAuth
// @Accept json
// @Produce text/event-stream
// @Param body body object true "Request body" example({"assetId":"550e8400-e29b-41d4-a716-446655440000"})
// @Success 200 {string} string "SSE stream (event: log | done | error)"
// @Failure 400 {object} echo.HTTPError "Invalid or missing assetId"
// @Failure 429 {object} echo.HTTPError "Cooldown not elapsed – try again later"
// @Router /admin/daemons/asset-pipeline-single/trigger [post]
func (c *AdminController) TriggerAssetPipelineSingle(ctx shared.Context) error {
	var req struct {
		AssetID string `json:"assetId"`
	}
	if err := ctx.Bind(&req); err != nil {
		return echo.NewHTTPError(400, "invalid request body")
	}
	if req.AssetID == "" {
		return echo.NewHTTPError(400, "assetId is required")
	}
	assetID, err := uuid.Parse(req.AssetID)
	if err != nil {
		return echo.NewHTTPError(400, "assetId must be a valid UUID")
	}

	// Use "." as separator to stay consistent with the dotted-path configKey
	// convention (a ":" would be an anomalous character in the DB key).
	configKey := "daemon.assetPipelineSingle." + assetID.String()
	return c.runDaemonSSE(ctx, configKey, "Asset Pipeline ("+assetID.String()+")", func(sse *sseWriter) error {
		return c.daemonRunner.RunDaemonPipelineForAsset(assetID)
	})
}

// --------------------------------------------------------------------------
// Core SSE runner
// --------------------------------------------------------------------------

// runDaemonSSE is the shared helper that:
//  1. Checks the 5-minute cooldown via the config DB.
//  2. Marks the trigger in the config DB before processing starts.
//  3. Opens an SSE stream and executes fn synchronously, streaming logs.
//  4. Sends a done or error event when finished.
//
// configKey is the config DB key used for both cooldown tracking and updating
// the last-run timestamp. For daemons that share a key with the automatic
// scheduler (e.g. "vulndb.vulndb"), the manual trigger also resets the
// automatic 12-hour timer.
func (c *AdminController) runDaemonSSE(
	ctx shared.Context,
	configKey string,
	label string,
	fn func(sse *sseWriter) error,
) error {
	session := shared.GetSession(ctx)
	userID := session.GetUserID()

	// ---- cooldown check (multi-instance safe via config DB) ----
	ok, retryAfter := c.checkCooldown(configKey)
	if !ok {
		secs := int(retryAfter.Seconds()) + 1
		return echo.NewHTTPError(429, fmt.Sprintf(
			"%s was triggered recently. Please try again in %d seconds.", label, secs,
		))
	}

	// Mark triggered NOW (before processing) so parallel requests / other
	// instances see the cooldown immediately.
	c.markTriggered(configKey)

	slog.Info("admin: triggering daemon via SSE", "key", configKey, "user", userID)

	// ---- open SSE stream ----
	sse := newSSEWriter(ctx.Response().Writer)
	sse.sendLog(fmt.Sprintf("Starting %s…", label))

	// Run synchronously inside the HTTP handler so the SSE stream stays open.
	func() {
		defer monitoring.RecoverPanic("admin: panic in " + configKey)
		if err := fn(sse); err != nil {
			slog.Error("admin: daemon failed", "key", configKey, "user", userID, "err", err)
			sse.sendError(err.Error())
			return
		}
		slog.Info("admin: daemon completed", "key", configKey, "user", userID)
		sse.sendDone()
	}()

	// The response is already committed (SSE headers + body sent).
	// Return nil so Echo does not try to write again.
	return nil
}
