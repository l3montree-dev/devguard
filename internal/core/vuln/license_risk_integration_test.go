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
package vuln_test

import (
	"testing"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core/vuln"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/stretchr/testify/assert"
)

func TestLicenseRiskArtifactAssociation(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create test org/project/asset/version
	_, _, _, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	// Create a component with an invalid license
	componentWithInvalidLicense := models.Component{
		Purl:    "pkg:npm/test-package@1.0.0",
		Version: "1.0.0",
		License: utils.Ptr("PROPRIETARY"),
	}

	// Persist the component (not strictly required for the service call, but keeps DB consistent)
	assert.NoError(t, db.Create(&componentWithInvalidLicense).Error)

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
	assert.NoError(t, db.Create(&artifact1).Error)
	assert.NoError(t, db.Create(&artifact2).Error)

	// Prepare repositories and services
	licenseRiskRepository := repositories.NewLicenseRiskRepository(db)
	vulnEventRepository := repositories.NewVulnEventRepository(db)
	licenseRiskService := vuln.NewLicenseRiskService(licenseRiskRepository, vulnEventRepository)

	// First run: detect risk for artifact-1
	err := licenseRiskService.FindLicenseRisksInComponents(assetVersion, []models.Component{componentWithInvalidLicense}, artifact1.ArtifactName)
	assert.NoError(t, err)

	// Verify license risk exists and is associated with artifact-1
	var risksAfterFirst []models.LicenseRisk
	err = db.Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetVersion.AssetID, assetVersion.Name).Find(&risksAfterFirst).Error
	assert.NoError(t, err)
	assert.Len(t, risksAfterFirst, 1)
	assert.Equal(t, "artifact-1", risksAfterFirst[0].Artifacts[0].ArtifactName)

	// Second run: process same component for artifact-2 and ensure association is created
	err = licenseRiskService.FindLicenseRisksInComponents(assetVersion, []models.Component{componentWithInvalidLicense}, artifact2.ArtifactName)
	assert.NoError(t, err)

	// Verify the license risk is now associated with both artifacts
	var risksFinal []models.LicenseRisk
	err = db.Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetVersion.AssetID, assetVersion.Name).Find(&risksFinal).Error
	assert.NoError(t, err)
	assert.Len(t, risksFinal, 1)
	// Collect artifact names
	names := make([]string, 0, len(risksFinal[0].Artifacts))
	for _, a := range risksFinal[0].Artifacts {
		names = append(names, a.ArtifactName)
	}
	assert.ElementsMatch(t, []string{"artifact-1", "artifact-2"}, names)

	// Sanity: ensure vuln events were created (at least one detected event)
	var events []models.VulnEvent
	err = db.Where("vuln_type = ?", models.VulnTypeLicenseRisk).Find(&events).Error
	assert.NoError(t, err)
	assert.Equal(t, 1, len(events))
}
