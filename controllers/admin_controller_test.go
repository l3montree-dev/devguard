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
	"context"
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

// adminTestDeps bundles all dependencies required by NewAdminController.
type adminTestDeps struct {
	daemonRunner      *mocks.DaemonRunner
	adminService      *mocks.AdminService
	adminRepository   *mocks.AdminRepository
	statisticsService *mocks.StatisticsService
	assetService      *mocks.AssetService
	configService     *mocks.ConfigService
}

// newAdminController constructs an AdminController with the test dependencies.
func newAdminController(d adminTestDeps) *AdminController {
	return NewAdminController(
		d.daemonRunner,
		d.adminService,
		d.adminRepository,
		d.statisticsService,
		d.assetService,
		d.configService,
	)
}

// setupMocks creates common mock dependencies.
// The configService is set up to allow the cooldown check (GetJSONConfig returns gorm.ErrRecordNotFound)
// and the trigger mark (SetJSONConfig returns nil) by default.
func setupMocks(t *testing.T) adminTestDeps {
	deps := adminTestDeps{
		daemonRunner:      mocks.NewDaemonRunner(t),
		adminService:      mocks.NewAdminService(t),
		adminRepository:   mocks.NewAdminRepository(t),
		statisticsService: mocks.NewStatisticsService(t),
		assetService:      mocks.NewAssetService(t),
		configService:     mocks.NewConfigService(t),
	}

	// By default: no previous trigger → cooldown passes
	deps.configService.EXPECT().GetJSONConfig(mock.Anything, mock.Anything, mock.Anything).
		Return(gorm.ErrRecordNotFound).Maybe()
	// By default: marking triggered succeeds
	deps.configService.EXPECT().SetJSONConfig(mock.Anything, mock.Anything, mock.Anything).
		Return(nil).Maybe()

	return deps
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
		deps := setupMocks(t)
		controller := newAdminController(deps)

		ctx, _ := newAdminTestContext(http.MethodPost, "/admin/daemons/asset-pipeline-single/trigger", `{}`)

		err := controller.TriggerAssetPipelineSingle(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 400, httpErr.Code)
	})

	t.Run("should return 400 if assetId is not a valid UUID", func(t *testing.T) {
		deps := setupMocks(t)
		controller := newAdminController(deps)

		ctx, _ := newAdminTestContext(http.MethodPost, "/admin/daemons/asset-pipeline-single/trigger", `{"assetId": "not-a-uuid"}`)

		err := controller.TriggerAssetPipelineSingle(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 400, httpErr.Code)
	})

	t.Run("should stream SSE events for valid assetId", func(t *testing.T) {
		deps := setupMocks(t)
		controller := newAdminController(deps)

		assetID := uuid.New()
		deps.daemonRunner.EXPECT().RunDaemonPipelineForAsset(mock.Anything, assetID).Return(nil)

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
		deps := setupMocks(t)
		controller := newAdminController(deps)

		deps.daemonRunner.EXPECT().RunAssetPipeline(mock.Anything, true).Return()

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
		deps := setupMocks(t)
		controller := newAdminController(deps)

		deps.daemonRunner.EXPECT().UpdateOpenSourceInsightInformation(mock.Anything).Return(nil)

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
		deps := setupMocks(t)
		controller := newAdminController(deps)

		deps.daemonRunner.EXPECT().UpdateVulnDB(mock.Anything).Return(nil)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/vulndb/trigger", "")

		err := controller.TriggerVulnDB(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))

		events := parseSSEEvents(rec.Body.String())
		assert.Equal(t, "done", events[len(events)-1].Event)
	})
}

func TestAdminController_TriggerFixedVersions(t *testing.T) {
	t.Run("should stream SSE and call UpdateFixedVersions", func(t *testing.T) {
		deps := setupMocks(t)
		controller := newAdminController(deps)

		deps.daemonRunner.EXPECT().UpdateFixedVersions(mock.Anything).Return(nil)

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
		deps := adminTestDeps{
			daemonRunner:      mocks.NewDaemonRunner(t),
			adminService:      mocks.NewAdminService(t),
			adminRepository:   mocks.NewAdminRepository(t),
			statisticsService: mocks.NewStatisticsService(t),
			assetService:      mocks.NewAssetService(t),
			configService:     mocks.NewConfigService(t),
		}

		// Simulate a recent trigger: GetJSONConfig sets the time to 1 minute ago
		recentTime := time.Now().Add(-1 * time.Minute)
		deps.configService.EXPECT().GetJSONConfig(mock.Anything, mock.Anything, mock.Anything).
			Run(func(_ context.Context, _ string, v any) {
				if ts, ok := v.(*daemonTriggerTimestamp); ok {
					ts.Time = recentTime
				}
			}).
			Return(nil)

		controller := newAdminController(deps)

		ctx, _ := newAdminTestContext(http.MethodPost, "/admin/daemons/fixed-versions/trigger", "")

		err := controller.TriggerFixedVersions(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 429, httpErr.Code)
		assert.Contains(t, httpErr.Message, "try again")
	})

	t.Run("should allow trigger when cooldown has elapsed", func(t *testing.T) {
		deps := adminTestDeps{
			daemonRunner:      mocks.NewDaemonRunner(t),
			adminService:      mocks.NewAdminService(t),
			adminRepository:   mocks.NewAdminRepository(t),
			statisticsService: mocks.NewStatisticsService(t),
			assetService:      mocks.NewAssetService(t),
			configService:     mocks.NewConfigService(t),
		}

		// Simulate an old trigger: 10 minutes ago
		oldTime := time.Now().Add(-10 * time.Minute)
		deps.configService.EXPECT().GetJSONConfig(mock.Anything, mock.Anything, mock.Anything).
			Run(func(_ context.Context, _ string, v any) {
				if ts, ok := v.(*daemonTriggerTimestamp); ok {
					ts.Time = oldTime
				}
			}).
			Return(nil)
		deps.configService.EXPECT().SetJSONConfig(mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

		deps.daemonRunner.EXPECT().UpdateFixedVersions(mock.Anything).Return(nil)

		controller := newAdminController(deps)

		ctx, rec := newAdminTestContext(http.MethodPost, "/admin/daemons/fixed-versions/trigger", "")

		err := controller.TriggerFixedVersions(ctx)
		assert.NoError(t, err)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
	})
}

func TestAdminController_SSEErrorEvent(t *testing.T) {
	t.Run("should send error event when daemon fails", func(t *testing.T) {
		deps := setupMocks(t)
		controller := newAdminController(deps)

		deps.daemonRunner.EXPECT().UpdateFixedVersions(mock.Anything).Return(assert.AnError)

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
var _ shared.ConfigService = (*mocks.ConfigService)(nil)
