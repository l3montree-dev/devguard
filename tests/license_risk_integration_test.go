// Copyright (C) 2024 Tim Bastin, l3montree GmbH
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
package tests

import (
	"bytes"
	"io"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"go.uber.org/fx"
)

func TestLicenseRiskArtifactAssociation(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		// Create test org/project/asset/version using FX helper
		_, _, _, assetVersion := f.CreateOrgProjectAssetAndVersion()

		t.Run("License risk is created and associated with multiple artifacts", func(t *testing.T) {
			// Create a component with an invalid license
			componentWithInvalidLicense := models.Component{
				Purl:    "pkg:npm/test-package@1.0.0",
				Version: "1.0.0",
				License: utils.Ptr("PROPRIETARY"),
			}

			// Persist the component
			assert.NoError(t, f.DB.Create(&componentWithInvalidLicense).Error)

			// Create two artifact records
			artifact1 := models.Artifact{
				ArtifactName:     "artifact-1",
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
			}
			artifact2 := models.Artifact{
				ArtifactName:     "artifact-2",
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
			}
			assert.NoError(t, f.DB.Create(&artifact1).Error)
			assert.NoError(t, f.DB.Create(&artifact2).Error)

			// First run: detect risk for artifact-1 using FX-injected service
			err := f.App.LicenseRiskService.FindLicenseRisksInComponents(assetVersion, []models.Component{componentWithInvalidLicense}, artifact1.ArtifactName, dtos.UpstreamStateInternal)
			assert.NoError(t, err)

			// Verify license risk exists and is associated with artifact-1
			var risksAfterFirst []models.LicenseRisk
			err = f.DB.Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetVersion.AssetID, assetVersion.Name).Find(&risksAfterFirst).Error
			assert.NoError(t, err)
			assert.Len(t, risksAfterFirst, 1)
			assert.Equal(t, "artifact-1", risksAfterFirst[0].Artifacts[0].ArtifactName)

			// Second run: process same component for artifact-2
			err = f.App.LicenseRiskService.FindLicenseRisksInComponents(assetVersion, []models.Component{componentWithInvalidLicense}, artifact2.ArtifactName, dtos.UpstreamStateInternal)
			assert.NoError(t, err)

			// Verify the license risk is now associated with both artifacts
			var risksFinal []models.LicenseRisk
			err = f.DB.Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetVersion.AssetID, assetVersion.Name).Find(&risksFinal).Error
			assert.NoError(t, err)
			assert.Len(t, risksFinal, 1)

			// Collect artifact names
			names := make([]string, 0, len(risksFinal[0].Artifacts))
			for _, a := range risksFinal[0].Artifacts {
				names = append(names, a.ArtifactName)
			}
			assert.ElementsMatch(t, []string{"artifact-1", "artifact-2"}, names)

			// Sanity: ensure vuln events were created
			var events []models.VulnEvent
			err = f.DB.Where("vuln_type = ?", dtos.VulnTypeLicenseRisk).Find(&events).Error
			assert.NoError(t, err)
			assert.Equal(t, 1, len(events))
		})
	})
}

func getSBOMWithWithLicenseRisk() io.Reader {
	file, err := os.Open("testdata/sbom-with-license-risk.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	content, err := io.ReadAll(file)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(content)
}

func TestLicenseRiskLifecycleManagement(t *testing.T) {
	artifactName := "main"

	mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)
	mockOpenSourceInsightService.On("GetVersion", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(dtos.OpenSourceInsightsVersionResponse{
		Licenses: []string{},
	}, nil)

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{
		SuppressLogs: true,
		ExtraOptions: []fx.Option{
			fx.Decorate(func() shared.OpenSourceInsightService {
				return mockOpenSourceInsightService
			}),
		},
	}, func(f *TestFixture) {
		controller := f.App.ScanController

		app := echo.New()

		org, project, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		setupContext := func(ctx shared.Context) {
			authSession := mocks.NewAuthSession(t)
			authSession.On("GetUserID").Return("abc")
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, authSession)
		}

		artifact := models.Artifact{
			ArtifactName:     artifactName,
			AssetID:          asset.ID,
			AssetVersionName: assetVersion.Name,
		}
		assert.NoError(t, f.DB.Create(&artifact).Error)

		t.Run("should copy all events when license risk is found on different branches", func(t *testing.T) {
			recorder := httptest.NewRecorder()
			sbomFile := getSBOMWithWithLicenseRisk()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", assetVersion.Name)
			ctx := app.NewContext(req, recorder)
			setupContext(ctx)

			err := controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Use FX-injected repository (now with GetByAssetID in interface)
			risks, err := f.App.LicenseRiskRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, risks, 1)

			// accept the risk
			risk := risks[0]
			assert.Equal(t, dtos.VulnStateOpen, risk.State)

			risk.State = dtos.VulnStateAccepted
			assert.NoError(t, f.DB.Save(&risk).Error)

			// create a new asset version to simulate a scan from a different branch
			newAssetVersion := models.AssetVersion{
				AssetID: asset.ID,
				Name:    "feature-branch",
			}
			assert.NoError(t, f.DB.Create(&newAssetVersion).Error)

			recorder = httptest.NewRecorder()
			sbomFile = getSBOMWithWithLicenseRisk()
			req = httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomFile)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", "main")
			req.Header.Set("X-Asset-Ref", newAssetVersion.Name)
			ctx = app.NewContext(req, recorder)
			setupContext(ctx)

			err = controller.ScanDependencyVulnFromProject(ctx)
			assert.Nil(t, err)
			assert.Equal(t, 200, recorder.Code)

			// Use FX-injected repository (now with GetByAssetID in interface)
			risks, err = f.App.LicenseRiskRepository.GetByAssetID(nil, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, risks, 2)

			risks, err = f.App.LicenseRiskRepository.GetLicenseRisksByOtherAssetVersions(nil, newAssetVersion.Name, asset.ID)
			assert.Nil(t, err)
			assert.Len(t, risks, 1)
			newRisk := risks[0]
			assert.Equal(t, dtos.VulnStateAccepted, newRisk.State)
		})
	})
}
