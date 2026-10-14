package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestSyncExternalReferences(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		app := echo.New()
		createCVE2025_46569(f.DB)
		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		setupScanContext := func(ctx shared.Context) {
			authSession := NewUserSession(t, "test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		setupSyncContext := func(ctx shared.Context) {
			authSession := NewUserSession(t, "test-user")
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

			authSession := NewUserSession(t, "test-user")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetAssetVersion(ctx, emptyVersion)
			shared.SetSession(ctx, authSession)

			err := f.App.ExternalReferenceController.Sync(ctx)
			assert.NoError(t, err)
			assert.Equal(t, 200, recorder.Code)
		})

		// a separate version keeps these artifacts out of the controller syncs above
		upstreamVersion := f.CreateAssetVersion(asset.ID, "upstream-branch", false)

		var upstreamSBOM atomic.Value
		upstreamSBOM.Store(getSBOMWithVulnerabilityContent())
		var upstreamRequests atomic.Int32
		upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(upstreamSBOM.Load().([]byte))
		}))
		defer upstreamServer.Close()

		localArtifact := models.Artifact{
			ArtifactName:     "local-artifact",
			AssetVersionName: upstreamVersion.Name,
			AssetID:          asset.ID,
		}
		err := f.DB.Create(&localArtifact).Error
		assert.NoError(t, err)
		err = SeedDirectDependencies(f.DB, upstreamVersion, localArtifact.ArtifactName, "pkg:npm/local-package@1.0.0")
		assert.NoError(t, err)

		upstreamArtifact := models.Artifact{
			ArtifactName:     "upstream-artifact",
			AssetVersionName: upstreamVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&upstreamArtifact).Error
		assert.NoError(t, err)
		// an outdated revision of the upstream source, so the first sync sees a change
		err = SeedSBOM(f.DB, upstreamVersion, upstreamArtifact.ArtifactName, upstreamServer.URL, map[string][]string{sbomSeedRoot: {}})
		assert.NoError(t, err)

		syncIfChanged := func(t *testing.T, artifact models.Artifact) bool {
			rescanned, err := f.App.ScanService.SyncArtifactUpstreamSBOMSourcesIfChanged(context.Background(), f.DB, org, project, asset, upstreamVersion, artifact, "system", nil)
			assert.NoError(t, err)
			return rescanned
		}

		loadUpstreamSBOM := func(t *testing.T) models.SBOM {
			var sbom models.SBOM
			err := f.DB.First(&sbom, "asset_id = ? AND asset_version_name = ? AND artifact_name = ? AND source = ?", asset.ID, upstreamVersion.Name, upstreamArtifact.ArtifactName, upstreamServer.URL).Error
			assert.NoError(t, err)
			return sbom
		}

		loadVulns := func(t *testing.T) []models.DependencyVuln {
			var vulnerabilities []models.DependencyVuln
			err := f.DB.Find(&vulnerabilities, "asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, upstreamVersion.Name, "CVE-2025-46569").Error
			assert.NoError(t, err)
			return vulnerabilities
		}

		t.Run("should skip artifacts without upstream sources", func(t *testing.T) {
			assert.False(t, syncIfChanged(t, localArtifact))
			assert.Equal(t, int32(0), upstreamRequests.Load(), "should not fetch anything without upstream sources")
		})

		t.Run("should rescan when the upstream sbom changed", func(t *testing.T) {
			assert.True(t, syncIfChanged(t, upstreamArtifact))

			vulnerabilities := loadVulns(t)
			assert.NotEmpty(t, vulnerabilities, "should detect the vulnerability of the new upstream sbom")
			for _, vuln := range vulnerabilities {
				assert.Equal(t, dtos.VulnStateOpen, vuln.State)
			}
		})

		t.Run("should not rescan or rewrite an unchanged upstream sbom", func(t *testing.T) {
			before := loadUpstreamSBOM(t)

			assert.False(t, syncIfChanged(t, upstreamArtifact))

			after := loadUpstreamSBOM(t)
			assert.Equal(t, before.RootSubtreeHash, after.RootSubtreeHash)
			assert.True(t, before.UpdatedAt.Equal(after.UpdatedAt), "unchanged sbom should not be rewritten")
		})

		t.Run("should store the new revision and rescan when the upstream sbom changes again", func(t *testing.T) {
			before := loadUpstreamSBOM(t)
			upstreamSBOM.Store(getEmptySBOMContent())

			assert.True(t, syncIfChanged(t, upstreamArtifact))

			after := loadUpstreamSBOM(t)
			assert.NotEqual(t, before.RootSubtreeHash, after.RootSubtreeHash, "should store the new upstream revision")
		})
	})
}
