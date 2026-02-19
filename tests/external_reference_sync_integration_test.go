package tests

import (
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestSyncExternalReferences(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupScanContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		setupSyncContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetAssetVersion(ctx, assetVersion)
			shared.SetSession(ctx, authSession)
		}

		// Upload SBOMs for two artifacts so the sync has work to do
		for _, name := range []string{"sync-artifact-1", "sync-artifact-2"} {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/scan", sbomWithVulnerability())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", name)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", "main")
			req.Header.Set("X-Origin", "DEFAULT")
			ctx := app.NewContext(req, recorder)
			setupScanContext(ctx)

			err := f.App.ScanController.ScanDependencyVulnFromProject(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)
		}

		t.Run("should sync all artifacts in asset version", func(t *testing.T) {
			// Verify artifacts exist
			var artifacts []models.Artifact
			err := f.DB.Where("asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Find(&artifacts).Error
			assert.NoError(t, err)
			assert.GreaterOrEqual(t, len(artifacts), 2)

			// Count vulns before
			var countBefore int64
			f.DB.Model(&models.DependencyVuln{}).Where("asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Count(&countBefore)
			assert.Greater(t, countBefore, int64(0))

			// Call sync
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/external-references/sync/", nil)
			ctx := app.NewContext(req, recorder)
			setupSyncContext(ctx)

			err = f.App.ExternalReferenceController.Sync(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Vulns should remain stable
			var countAfter int64
			f.DB.Model(&models.DependencyVuln{}).Where("asset_id = ? AND asset_version_name = ?", asset.ID, assetVersion.Name).Count(&countAfter)
			assert.Equal(t, countBefore, countAfter)
		})

		t.Run("should succeed with no artifacts", func(t *testing.T) {
			emptyVersion := f.CreateAssetVersion(asset.ID, "empty-branch", false)

			recorder := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/external-references/sync/", nil)
			ctx := app.NewContext(req, recorder)

			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetAssetVersion(ctx, emptyVersion)
			shared.SetSession(ctx, authSession)

			err := f.App.ExternalReferenceController.Sync(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)
		})
	})
}
