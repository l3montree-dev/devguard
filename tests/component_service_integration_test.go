package tests

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGetAndSaveLicenseInformation(t *testing.T) {
	// Set up a mock OSI licenses API server that returns known valid licenses
	// This avoids external API dependencies in tests
	mockLicenses := `[
		{"spdx_id": "MIT"},
		{"spdx_id": "Apache-2.0"},
		{"spdx_id": "GPL-3.0-only"},
		{"spdx_id": "BSD-3-Clause"}
	]`

	// Create a simple HTTP server for testing
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockLicenses))
	}))
	defer server.Close()

	t.Run("should create license risk entries for components with invalid licenses", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			// Create test data using FX helper
			_, _, _, assetVersion := f.CreateOrgProjectAssetAndVersion()

			// Create test components with different license scenarios
			componentWithInvalidLicense := models.Component{
				Purl:    "pkg:npm/test-package@1.0.0",
				Version: "1.0.0",
				License: utils.Ptr("PROPRIETARY"), // Invalid OSI license
			}

			componentWithValidLicense := models.Component{
				Purl:    "pkg:npm/valid-package@1.0.0",
				Version: "1.0.0",
				License: utils.Ptr("MIT"), // Valid OSI license
			}

			componentWithoutLicense := models.Component{
				Purl:    "pkg:npm/no-license-package@1.0.0",
				Version: "1.0.0",
				License: nil, // No license - will be handled by GetLicense
			}

			// Save components to database
			err := f.DB.Create(&componentWithInvalidLicense).Error
			assert.NoError(t, err)
			err = f.DB.Create(&componentWithValidLicense).Error
			assert.NoError(t, err)
			err = f.DB.Create(&componentWithoutLicense).Error
			assert.NoError(t, err)

			// Create component dependencies
			artifact := models.Artifact{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
			}

			// First create the artifact
			err = f.DB.Create(&artifact).Error
			assert.NoError(t, err)

			componentDeps := []models.ComponentDependency{
				{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					DependencyPurl:   componentWithInvalidLicense.Purl,
					Dependency:       componentWithInvalidLicense,
				},
				{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					DependencyPurl:   componentWithValidLicense.Purl,
					Dependency:       componentWithValidLicense,
				},
				{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					DependencyPurl:   componentWithoutLicense.Purl,
					Dependency:       componentWithoutLicense,
				},
			}

			for _, dep := range componentDeps {
				err = f.DB.Create(&dep).Error
				assert.NoError(t, err)

				// Now create the many-to-many relationship with artifacts
				err = f.DB.Model(&dep).Association("Artifacts").Append(&artifact)
				assert.NoError(t, err)
			}

			// Mock the OpenSourceInsightService for the component without license
			mockOpenSourceInsightService := mocks.NewOpenSourceInsightService(t)

			// Mock response for the component without license - simulate getting "unknown" license
			mockOpenSourceInsightService.On("GetVersion", mock.Anything, "npm", "no-license-package", "1.0.0").
				Return(dtos.OpenSourceInsightsVersionResponse{
					Licenses: []string{}, // No licenses returned
				}, nil)

			// Call the function under test using FX-injected component service
			resultComponents, err := f.App.ComponentService.GetAndSaveLicenseInformation(assetVersion, utils.Ptr(artifact.ArtifactName), false, 0)
			assert.NoError(t, err)
			assert.NotEmpty(t, resultComponents)

			// Verify that license risks were created for components with invalid licenses
			var licenseRisks []models.LicenseRisk
			err = f.DB.Preload("Artifacts").Where("asset_id = ? AND asset_version_name = ?", assetVersion.AssetID, assetVersion.Name).Find(&licenseRisks).Error
			assert.NoError(t, err)

			// We should have license risks for:
			// 1. componentWithInvalidLicense (PROPRIETARY license)
			// 2. componentWithoutLicense (will get "unknown" license which is invalid)
			expectedRiskCount := 2
			assert.Equal(t, expectedRiskCount, len(licenseRisks))

			// Check specific license risk entries
			licenseRiskPurls := make(map[string]models.LicenseRisk)
			for _, risk := range licenseRisks {
				licenseRiskPurls[risk.ComponentPurl] = risk
			}

			// Verify license risk for component with invalid license
			invalidLicenseRisk, exists := licenseRiskPurls[componentWithInvalidLicense.Purl]
			assert.True(t, exists, "License risk should exist for component with invalid license")
			assert.Equal(t, dtos.VulnStateOpen, invalidLicenseRisk.State)
			assert.Equal(t, artifact.ArtifactName, invalidLicenseRisk.Artifacts[0].ArtifactName)
			assert.Equal(t, assetVersion.AssetID, invalidLicenseRisk.AssetID)
			assert.Equal(t, assetVersion.Name, invalidLicenseRisk.AssetVersionName)

			// Verify license risk for component without license (should get "unknown")
			unknownLicenseRisk, exists := licenseRiskPurls[componentWithoutLicense.Purl]
			assert.True(t, exists, "License risk should exist for component with unknown license")
			assert.Equal(t, dtos.VulnStateOpen, unknownLicenseRisk.State)

			// Verify NO license risk was created for component with valid license
			_, exists = licenseRiskPurls[componentWithValidLicense.Purl]
			assert.False(t, exists, "No license risk should exist for component with valid license")

			// Verify that corresponding vuln events were created
			var vulnEvents []models.VulnEvent
			err = f.DB.Where("vuln_type = ?", dtos.VulnTypeLicenseRisk).Find(&vulnEvents).Error
			assert.NoError(t, err)
			assert.Equal(t, expectedRiskCount, len(vulnEvents))

			// Verify vuln events are of correct type
			for _, event := range vulnEvents {
				assert.Equal(t, dtos.VulnTypeLicenseRisk, event.VulnType)
				assert.Equal(t, dtos.EventTypeDetected, event.Type)
				assert.Equal(t, "system", event.UserID)
			}

			t.Logf("Successfully created %d license risks and %d vuln events", len(licenseRisks), len(vulnEvents))
		})
	})

	t.Run("should not create duplicate license risks for existing entries", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			// Create test data using FX helper
			_, _, _, assetVersion := f.CreateOrgProjectAssetAndVersion()

			// Create component with invalid license
			componentWithInvalidLicense := models.Component{
				Purl:    "pkg:npm/test-package@1.0.0",
				Version: "1.0.0",
				License: utils.Ptr("PROPRIETARY"),
			}
			err := f.DB.Create(&componentWithInvalidLicense).Error
			assert.NoError(t, err)

			artifact := models.Artifact{
				ArtifactName:     "artifact1",
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
			}

			// First create the artifact
			err = f.DB.Create(&artifact).Error
			assert.NoError(t, err)

			// Create component dependency
			componentDep := models.ComponentDependency{
				AssetVersionName: assetVersion.Name,
				AssetID:          assetVersion.AssetID,
				DependencyPurl:   componentWithInvalidLicense.Purl,
				Dependency:       componentWithInvalidLicense,
			}
			err = f.DB.Create(&componentDep).Error
			assert.NoError(t, err)

			// Create the many-to-many relationship with artifacts
			err = f.DB.Model(&componentDep).Association("Artifacts").Append(&artifact)
			assert.NoError(t, err)

			// Create existing license risk
			existingLicenseRisk := models.LicenseRisk{
				Vulnerability: models.Vulnerability{
					AssetVersionName: assetVersion.Name,
					AssetID:          assetVersion.AssetID,
					State:            dtos.VulnStateOpen,
				},
				Artifacts:     []models.Artifact{artifact},
				ComponentPurl: componentWithInvalidLicense.Purl,
			}
			// Manually set the ID using the same calculation as the model
			existingLicenseRisk.ID = existingLicenseRisk.CalculateHash()
			err = f.DB.Create(&existingLicenseRisk).Error
			assert.NoError(t, err)

			// Call the function under test using FX-injected component service
			_, err = f.App.ComponentService.GetAndSaveLicenseInformation(assetVersion, utils.Ptr(artifact.ArtifactName), false, 0)
			assert.NoError(t, err)

			// Verify that no duplicate license risk was created
			var licenseRisks []models.LicenseRisk
			err = f.DB.Where("asset_id = ? AND asset_version_name = ?", assetVersion.AssetID, assetVersion.Name).Find(&licenseRisks).Error
			assert.NoError(t, err)

			// Should still have only 1 license risk (the existing one)
			assert.Equal(t, 1, len(licenseRisks))
			assert.Equal(t, existingLicenseRisk.ID, licenseRisks[0].ID)

			t.Log("Successfully avoided creating duplicate license risk entries")
		})
	})
}
