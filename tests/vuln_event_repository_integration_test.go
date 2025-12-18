package tests

import (
	"fmt"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestCreateBatchWithUnnest(t *testing.T) {

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{}, func(f *TestFixture) {
		// Create org, project, asset, and asset version using FX helper
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		vulnEventRepo := repositories.NewVulnEventRepository(f.DB)

		t.Run("should create only one ticket when vuln exists in two artifacts", func(t *testing.T) {
			// Create a CVE
			cve := models.CVE{
				CVE:              "CVE-2024-12345",
				Description:      "Test critical vulnerability",
				CVSS:             9.8,
				Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				DatePublished:    assetVersion.CreatedAt,
				DateLastModified: assetVersion.UpdatedAt,
			}
			assert.NoError(t, f.DB.Create(&cve).Error)

			artifact1 := models.Artifact{
				ArtifactName:     "artifact-1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.NoError(t, f.DB.Create(&artifact1).Error)

			// Create a dependency vuln to reference
			depVuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					State:            dtos.VulnStateOpen,
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
				},
				CVEID:          utils.Ptr(cve.CVE),
				ComponentPurl:  utils.Ptr("pkg:npm/vulnerable-package@1.0.0"),
				ComponentDepth: utils.Ptr(0),
				Artifacts:      []models.Artifact{artifact1},
			}

			// create a base event
			event := models.VulnEvent{
				VulnID:                   depVuln.CalculateHash(),
				OriginalAssetVersionName: &assetVersion.Name,
			}

			// create 20 vuln events with different values
			allEvents := make([]models.VulnEvent, 20)
			for i := range allEvents {
				modEvent := event
				modEvent.Justification = utils.Ptr(fmt.Sprintf("This is the %d. justification", i))
				if i == 0 {
					modEvent.Type = dtos.EventTypeDetected
				} else {
					modEvent.Type = dtos.EventTypeMitigate
				}
				allEvents[i] = modEvent
			}

			err := vulnEventRepo.CreateBatchWithUnnest(nil, allEvents)
			assert.NoError(t, err)

			fetchedEvents, err := vulnEventRepo.All()
			assert.NoError(t, err)

			assert.Len(t, allEvents, 20)
			// test each queried event for their respective values
			for i, event := range fetchedEvents {
				if i == 0 {
					assert.Equal(t, dtos.EventTypeDetected, event.Type)
				} else {
					assert.Equal(t, dtos.EventTypeMitigate, event.Type)
				}

				assert.Equal(t, event.Justification, utils.Ptr(fmt.Sprintf("This is the %d. justification", i)))
			}
		})
	})
}
