package scan

import (
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

type controllerMocks struct {
	AssetVersionRepository *mocks.AssetVersionRepository
	AssetVersionService    *mocks.AssetVersionService
	SBOMScanner            *mocks.SBOMScanner
	DependencyVulnService  *mocks.DependencyVulnService
	StatisticsService      *mocks.StatisticsService
}

func newMockedHttpController(t *testing.T) (httpController, *controllerMocks) {
	m := &controllerMocks{
		AssetVersionRepository: mocks.NewAssetVersionRepository(t),
		AssetVersionService:    mocks.NewAssetVersionService(t),
		SBOMScanner:            mocks.NewSBOMScanner(t),
		DependencyVulnService:  mocks.NewDependencyVulnService(t),
		StatisticsService:      mocks.NewStatisticsService(t),
	}
	return httpController{
		assetVersionRepository: m.AssetVersionRepository,
		assetVersionService:    m.AssetVersionService,
		sbomScanner:            m.SBOMScanner,
		dependencyVulnService:  m.DependencyVulnService,
		statisticsService:      m.StatisticsService,
	}, m
}

func newTestEchoContext(t *testing.T, headers map[string]string) echo.Context {
	app := echo.New()
	req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	ctx := app.NewContext(req, nil)
	core.SetAsset(ctx, models.Asset{})
	authSession := mocks.NewAuthSession(t)
	authSession.On("GetUserID").Return("abc")
	core.SetSession(ctx, authSession)
	return ctx
}

func TestScanNormalizedSboms(t *testing.T) {

	t.Run("should respect the X-Tag header (1)", func(t *testing.T) {
		httpController, mocks := newMockedHttpController(t)
		mocks.AssetVersionRepository.On("FindOrCreate", "main", mock.Anything, true, mock.Anything).Return(models.AssetVersion{}, nil)

		ctx := newTestEchoContext(t, map[string]string{"X-Tag": "1"})
		httpController.DependencyVulnScan(ctx, nil) //nolint:errcheck
	})

	t.Run("should respect the X-Tag header (0)", func(t *testing.T) {
		httpController, mocks := newMockedHttpController(t)
		mocks.AssetVersionRepository.On("FindOrCreate", "main", mock.Anything, false, mock.Anything).Return(models.AssetVersion{}, nil)

		ctx := newTestEchoContext(t, map[string]string{"X-Tag": "0"})
		httpController.DependencyVulnScan(ctx, nil) //nolint:errcheck
	})

	t.Run("should fallback to the main asset version if assetVersionName is not set", func(t *testing.T) {
		httpController, mocks := newMockedHttpController(t)
		mocks.AssetVersionRepository.On("FindOrCreate", "main", mock.Anything, mock.Anything, mock.Anything).Return(models.AssetVersion{}, nil)

		ctx := newTestEchoContext(t, nil)
		httpController.DependencyVulnScan(ctx, nil) //nolint:errcheck
	})

	t.Run("should not return already fixed dependency vulnerabilities as scan result", func(t *testing.T) {
		httpController, mocks := newMockedHttpController(t)
		mocks.AssetVersionRepository.On("FindOrCreate", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(models.AssetVersion{}, nil)
		mocks.AssetVersionRepository.On("Save", mock.Anything, mock.Anything).Return(nil)
		mocks.AssetVersionService.On("UpdateSBOM", mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mocks.SBOMScanner.On("Scan", mock.Anything).Return(nil, nil)
		mocks.AssetVersionService.On("HandleScanResult", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
			[]models.DependencyVuln{}, []models.DependencyVuln{}, []models.DependencyVuln{
				{Vulnerability: models.Vulnerability{State: models.VulnStateAccepted}},
				{Vulnerability: models.Vulnerability{State: models.VulnStateFixed}},
			}, nil,
		)
		mocks.StatisticsService.On("UpdateAssetRiskAggregation", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
		mocks.DependencyVulnService.On("ShouldCreateIssues", mock.Anything, mock.Anything).Return(false)

		ctx := newTestEchoContext(t, map[string]string{"X-Scanner": "test-scanner"})
		scanResponse, _ := httpController.DependencyVulnScan(ctx, nil)

		if len(scanResponse.DependencyVulns) != 1 {
			t.Errorf("expected 1 vulnerability in scan response, got %d", len(scanResponse.DependencyVulns))
		}
	})
}
