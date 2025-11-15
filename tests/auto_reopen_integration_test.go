package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/daemons"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestAutoReopenAcceptedVulnerabilities(t *testing.T) {
	db, terminate := InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	// Create test data
	_, project, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	// Set up repositories
	assetRepo := repositories.NewAssetRepository(db)
	dependencyVulnRepo := repositories.NewDependencyVulnRepository(db)

	t.Run("should not reopen vulnerabilities if auto-reopen is not configured", func(t *testing.T) {
		// Ensure asset has no auto-reopen configuration
		asset.VulnAutoReopenAfterDays = nil
		err := assetRepo.Update(db, &asset)
		assert.NoError(t, err)

		// Create a vulnerability that was accepted 2 hours ago
		vulnerability := createTestVulnerability(t, db, asset, assetVersion, 2*time.Hour)
		acceptVulnerability(t, db, &vulnerability, 2*time.Hour)

		// Run auto-reopen
		err = daemons.AutoReopenAcceptedVulnerabilities(db)
		assert.NoError(t, err)

		// Verify vulnerability is still accepted
		updatedVuln, err := dependencyVulnRepo.Read(vulnerability.ID)
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateAccepted, updatedVuln.State)
	})

	t.Run("should not reopen vulnerabilities that are within the time threshold", func(t *testing.T) {
		// Configure asset for auto-reopen after 1 day
		autoReopenAfterDays := 1
		asset.VulnAutoReopenAfterDays = &autoReopenAfterDays
		err := assetRepo.Update(db, &asset)
		assert.NoError(t, err)

		// Create a vulnerability that was accepted 1 hour ago (within threshold)
		vulnerability := createTestVulnerability(t, db, asset, assetVersion, 1*time.Hour)
		acceptVulnerability(t, db, &vulnerability, 1*time.Hour)

		// Run auto-reopen
		err = daemons.AutoReopenAcceptedVulnerabilities(db)
		assert.NoError(t, err)

		// Verify vulnerability is still accepted
		updatedVuln, err := dependencyVulnRepo.Read(vulnerability.ID)
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateAccepted, updatedVuln.State)
	})

	t.Run("should reopen vulnerabilities that exceed the time threshold", func(t *testing.T) {
		// Configure asset for auto-reopen after 1 day
		autoReopenAfterDays := 1
		asset.VulnAutoReopenAfterDays = &autoReopenAfterDays
		err := assetRepo.Update(db, &asset)
		assert.NoError(t, err)

		// Create a vulnerability that was accepted 2 days ago (exceeds threshold)
		vulnerability := createTestVulnerability(t, db, asset, assetVersion, 48*time.Hour)
		acceptVulnerability(t, db, &vulnerability, 48*time.Hour)

		// Run auto-reopen
		err = daemons.AutoReopenAcceptedVulnerabilities(db)
		assert.NoError(t, err)

		// Verify vulnerability has been reopened
		updatedVuln, err := dependencyVulnRepo.Read(vulnerability.ID)
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateOpen, updatedVuln.State)

		// Verify a reopen event was created
		events := updatedVuln.Events
		assert.NotEmpty(t, events)

		// Find the reopen event
		var reopenEvent *models.VulnEvent
		for _, event := range events {
			if event.Type == dtos.EventTypeReopened {
				reopenEvent = &event
				break
			}
		}

		assert.NotNil(t, reopenEvent, "Expected to find a reopen event")
		assert.Equal(t, "system", reopenEvent.UserID)
		assert.NotNil(t, reopenEvent.Justification, "Expected justification to not be nil")
		assert.Contains(t, *reopenEvent.Justification, "Automatically reopened")
	})

	t.Run("should handle multiple assets with different configurations", func(t *testing.T) {
		// Create another asset with different auto-reopen configuration
		asset2 := models.Asset{
			Name:        "test-asset-2",
			Slug:        "test-asset-2",
			ProjectID:   project.ID,
			Type:        models.AssetTypeApplication,
			Description: "Test asset 2",
		}
		autoReopenAfter2Days := 2
		asset2.VulnAutoReopenAfterDays = &autoReopenAfter2Days
		err := assetRepo.Create(db, &asset2)
		assert.NoError(t, err)

		assetVersion2 := models.AssetVersion{
			AssetID:       asset2.ID,
			Name:          "main",
			DefaultBranch: true,
		}
		assetVersionRepo := repositories.NewAssetVersionRepository(db)
		err = assetVersionRepo.Create(db, &assetVersion2)
		assert.NoError(t, err)

		// Set different auto-reopen thresholds
		autoReopenAfter1Days := 1
		asset.VulnAutoReopenAfterDays = &autoReopenAfter1Days
		err = assetRepo.Update(db, &asset)
		assert.NoError(t, err)

		// Create vulnerabilities for both assets
		vuln1 := createTestVulnerability(t, db, asset, assetVersion, 1*time.Hour)
		acceptVulnerability(t, db, &vuln1, 36*time.Hour) // Accepted 1.5 days ago

		vuln2 := createTestVulnerability(t, db, asset2, assetVersion2, 2*time.Hour)
		acceptVulnerability(t, db, &vuln2, 72*time.Hour) // Accepted 3 days ago

		// Run auto-reopen
		err = daemons.AutoReopenAcceptedVulnerabilities(db)
		assert.NoError(t, err)

		// Verify both vulnerabilities are reopened
		updatedVuln1, err := dependencyVulnRepo.Read(vuln1.ID)
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateOpen, updatedVuln1.State)

		updatedVuln2, err := dependencyVulnRepo.Read(vuln2.ID)
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateOpen, updatedVuln2.State)
	})
}

// createTestVulnerability creates a test dependency vulnerability
func createTestVulnerability(t *testing.T, db shared.DB, asset models.Asset, assetVersion models.AssetVersion, timeAgo time.Duration) models.DependencyVuln {
	// Create a unique CVE ID for each test case
	cveID := fmt.Sprintf("CVE-2025-TEST-%d", time.Now().UnixNano())

	// Create a test CVE
	cve := models.CVE{
		CVE:              cveID,
		DatePublished:    time.Now().Add(-24 * time.Hour),
		DateLastModified: time.Now().Add(-12 * time.Hour),
		Description:      "Test vulnerability for auto-reopen testing",
		CVSS:             7.5,
	}
	err := db.Create(&cve).Error
	assert.NoError(t, err)

	// Create the vulnerability - ID will be auto-generated by BeforeSave hook
	vulnerability := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
			State:            dtos.VulnStateOpen,
			LastDetected:     time.Now().Add(-timeAgo),
		},
		CVEID:          utils.Ptr(cveID),
		ComponentPurl:  utils.Ptr("pkg:npm/test-package@1.0.0"),
		ComponentDepth: utils.Ptr(0),
		Artifacts: []models.Artifact{
			{ArtifactName: "test-artifact",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			},
		},
	}
	err = db.Create(&vulnerability).Error
	assert.NoError(t, err)

	return vulnerability
}

// acceptVulnerability creates an accepted event for a vulnerability
func acceptVulnerability(t *testing.T, db shared.DB, vulnerability *models.DependencyVuln, timeAgo time.Duration) {
	// Create an accepted event using the model constructor
	acceptEvent := models.NewAcceptedEvent(vulnerability.CalculateHash(), dtos.VulnTypeDependencyVuln, "test-user", "Accepted for testing", dtos.UpstreamStateInternal)

	// Manually set the creation time for testing
	acceptEvent.CreatedAt = time.Now().Add(-timeAgo)
	acceptEvent.UpdatedAt = time.Now().Add(-timeAgo)

	err := db.Create(&acceptEvent).Error
	assert.NoError(t, err)

	// Update vulnerability state
	vulnerability.State = dtos.VulnStateAccepted
	vulnerability.LastDetected = time.Now().Add(-timeAgo)
	err = db.Save(vulnerability).Error
	assert.NoError(t, err)
}
