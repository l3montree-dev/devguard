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
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/accesscontrol"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

// newAdminTestContext sets up an echo context with an admin session for testing.
func newAdminTestContext(method, path, body string) (echo.Context, *httptest.ResponseRecorder) {
	e := echo.New()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	session := accesscontrol.NewSession("admin-user-123", []string{"admin"}, true)
	shared.SetSession(ctx, session)

	return ctx, rec
}

// setupMocks creates common mock dependencies.
// The configService is set up to allow the cooldown check (GetJSONConfig returns gorm.ErrRecordNotFound)
// and the trigger mark (SetJSONConfig returns nil) by default.
func setupMocks(t *testing.T) (*mocks.DaemonRunner, *mocks.VulnDBImportService, *mocks.ConfigService) {
	daemonRunner := mocks.NewDaemonRunner(t)
	vulnDBService := mocks.NewVulnDBImportService(t)
	configService := mocks.NewConfigService(t)

	// By default: no previous trigger → cooldown passes
	configService.EXPECT().GetJSONConfig(mock.Anything, mock.Anything).
		Return(gorm.ErrRecordNotFound).Maybe()
	// By default: marking triggered succeeds
	configService.EXPECT().SetJSONConfig(mock.Anything, mock.Anything).
		Return(nil).Maybe()

	return daemonRunner, vulnDBService, configService
}

// parseSSEEvents reads SSE events from the recorder body.
func parseSSEEvents(body string) []struct{ Event, Data string } {
	var events []struct{ Event, Data string }
	scanner := bufio.NewScanner(strings.NewReader(body))
	var event, data string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "event: ") {
			event = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			data = strings.TrimPrefix(line, "data: ")
		} else if line == "" && event != "" {
			events = append(events, struct{ Event, Data string }{event, data})
			event, data = "", ""
		}
	}
	return events
}

func TestAdminController_TriggerAssetPipelineSingle(t *testing.T) {
	t.Run("should return 400 if body is missing assetId", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		ctx, _ := newAdminTestContext(http.MethodPost, "/admin/daemons/asset-pipeline-single/trigger", `{}`)

		err := controller.TriggerAssetPipelineSingle(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 400, httpErr.Code)
	})

	t.Run("should return 400 if assetId is not a valid UUID", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		ctx, _ := newAdminTestContext(http.MethodPost, "/admin/daemons/asset-pipeline-single/trigger", `{"assetId": "not-a-uuid"}`)

		err := controller.TriggerAssetPipelineSingle(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 400, httpErr.Code)
	})

	t.Run("should stream SSE events for valid assetId", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		assetID := uuid.New()
		daemonRunner.EXPECT().RunDaemonPipelineForAsset(assetID).Return(nil)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/asset-pipeline-single/trigger",
			`{"assetId": "`+assetID.String()+`"}`)

		err := controller.TriggerAssetPipelineSingle(ctx)
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.GreaterOrEqual(t, len(events), 2) // at least log + done
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_TriggerAssetPipelineAll(t *testing.T) {
	t.Run("should stream SSE events", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		daemonRunner.EXPECT().RunAssetPipeline(true).Return()

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/asset-pipeline-all/trigger", "")

		err := controller.TriggerAssetPipelineAll(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_TriggerOpenSourceInsights(t *testing.T) {
	t.Run("should stream SSE and call UpdateOpenSourceInsightInformation", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		daemonRunner.EXPECT().UpdateOpenSourceInsightInformation().Return(nil)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/open-source-insights/trigger", "")

		err := controller.TriggerOpenSourceInsights(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_TriggerVulnDB(t *testing.T) {
	t.Run("should set vulndb.vulndb timestamp and stream SSE", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		daemonRunner.EXPECT().UpdateVulnDB().Return(nil)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/vulndb/trigger", "")

		err := controller.TriggerVulnDB(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_TriggerVulnDBCleanup(t *testing.T) {
	t.Run("should stream SSE and call CleanupOrphanedTables", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		vulnDBService.EXPECT().CleanupOrphanedTables().Return(nil)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/vulndb-cleanup/trigger", "")

		err := controller.TriggerVulnDBCleanup(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_TriggerFixedVersions(t *testing.T) {
	t.Run("should stream SSE and call UpdateFixedVersions", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		daemonRunner.EXPECT().UpdateFixedVersions().Return(nil)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/fixed-versions/trigger", "")

		err := controller.TriggerFixedVersions(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_Cooldown(t *testing.T) {
	t.Run("should return 429 when triggered within cooldown period", func(t *testing.T) {
		daemonRunner := mocks.NewDaemonRunner(t)
		vulnDBService := mocks.NewVulnDBImportService(t)
		configService := mocks.NewConfigService(t)

		// Simulate a recent trigger: GetJSONConfig sets the time to 1 minute ago
		recentTime := time.Now().Add(-1 * time.Minute)
		configService.EXPECT().GetJSONConfig(mock.Anything, mock.Anything).
			Run(func(_ string, v any) {
				if ts, ok := v.(*daemonTriggerTimestamp); ok {
					ts.Time = recentTime
				}
			}).
			Return(nil)

		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		ctx, _ := newAdminTestContext(http.MethodPost, "/admin/daemons/fixed-versions/trigger", "")

		err := controller.TriggerFixedVersions(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 429, httpErr.Code)
		assert.Contains(t, httpErr.Message, "try again")
	})

	t.Run("should allow trigger when cooldown has elapsed", func(t *testing.T) {
		daemonRunner := mocks.NewDaemonRunner(t)
		vulnDBService := mocks.NewVulnDBImportService(t)
		configService := mocks.NewConfigService(t)

		// Simulate an old trigger: 10 minutes ago
		oldTime := time.Now().Add(-10 * time.Minute)
		configService.EXPECT().GetJSONConfig(mock.Anything, mock.Anything).
			Run(func(_ string, v any) {
				if ts, ok := v.(*daemonTriggerTimestamp); ok {
					ts.Time = oldTime
				}
			}).
			Return(nil)
		configService.EXPECT().SetJSONConfig(mock.Anything, mock.Anything).Return(nil).Maybe()

		daemonRunner.EXPECT().UpdateFixedVersions().Return(nil)

		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/fixed-versions/trigger", "")

		err := controller.TriggerFixedVersions(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	})
}

func TestAdminController_SSEErrorEvent(t *testing.T) {
	t.Run("should send error event when daemon fails", func(t *testing.T) {
		daemonRunner, vulnDBService, configService := setupMocks(t)
		controller := NewAdminController(daemonRunner, vulnDBService, configService)

		daemonRunner.EXPECT().UpdateFixedVersions().Return(assert.AnError)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/fixed-versions/trigger", "")

		err := controller.TriggerFixedVersions(ctx)
		assert.NoError(t, err) // SSE stream committed, no echo error

		events := parseSSEEvents(rec.Body.String())
		lastEvent := events[len(events)-1]
		assert.Equal(t, "error", lastEvent.Event)
	})
}

// Ensure the mock satisfies the interface
var _ shared.DaemonRunner = (*mocks.DaemonRunner)(nil)
var _ shared.VulnDBImportService = (*mocks.VulnDBImportService)(nil)
var _ shared.ConfigService = (*mocks.ConfigService)(nil)
