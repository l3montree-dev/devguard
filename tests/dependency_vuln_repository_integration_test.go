package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
)

func TestSaveBatchWithUnnest(t *testing.T) {

	WithTestAppOptions(t, "../initdb.sql", TestAppOptions{}, func(f *TestFixture) {
		// Create org, project, asset, and asset version using FX helper
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()
		depVulnRep := repositories.NewDependencyVulnRepository(f.DB)

		t.Run("should create only one ticket when vuln exists in two artifacts", func(t *testing.T) {
			// Create a CVE for the dependency vuln
			cve := models.CVE{
				CVE:              "CVE-2024-12345",
				Description:      "Test critical vulnerability",
				CVSS:             9.8,
				Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				DatePublished:    assetVersion.CreatedAt,
				DateLastModified: assetVersion.UpdatedAt,
			}
			assert.NoError(t, f.DB.Create(&cve).Error)

			// Create 2 artifacts for the dependency vulns
			artifact1 := models.Artifact{
				ArtifactName:     "artifact-1",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			artifact2 := models.Artifact{
				ArtifactName:     "artifact-2",
				AssetVersionName: assetVersion.Name,
				AssetID:          asset.ID,
			}
			assert.NoError(t, f.DB.Create(&artifact1).Error)
			assert.NoError(t, f.DB.Create(&artifact2).Error)

			// Create a dependency vuln associated with both artifacts
			depVuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					State:            dtos.VulnStateOpen,
					AssetVersionName: assetVersion.Name,
					AssetID:          asset.ID,
				},
				CVEID:          utils.Ptr(cve.CVE),
				ComponentPurl:  utils.Ptr("pkg:npm/vulnerable-package@1.0.0"),
				ComponentDepth: utils.Ptr(0),
				Artifacts:      []models.Artifact{artifact1, artifact2},
			}

			// create 10 dependency vulns with different purls
			allVulns := make([]models.DependencyVuln, 10)
			for i := range allVulns {
				vuln := depVuln
				vuln.ComponentPurl = utils.Ptr(fmt.Sprintf("pkg:npm/vulnerable-package@%d.0.0", i))
				allVulns[i] = vuln
			}

			assert.NoError(t, f.DB.Create(allVulns).Error)

			// update the values of each vuln and then save them to the db
			for i := range allVulns {
				allVulns[i].State = dtos.VulnStateFixed
				allVulns[i].Effort = utils.Ptr(20 * i)
				allVulns[i].ComponentDepth = utils.Ptr(2 * i)
				allVulns[i].ComponentFixedVersion = utils.Ptr(fmt.Sprintf("this is fixed in version: %d", i))
				allVulns[i].RiskAssessment = utils.Ptr(5)
				allVulns[i].RawRiskAssessment = utils.Ptr(4.2)
				allVulns[i].TicketID = utils.Ptr(fmt.Sprintf("gitlab:fantasy:%d", i))
				allVulns[i].RiskRecalculatedAt = time.Now()
			}
			err := depVulnRep.SaveBatchWithUnnest(nil, allVulns)
			assert.NoError(t, err)

			updateVulns, err := depVulnRep.All()
			assert.NoError(t, err)

			assert.Len(t, updateVulns, 10)
			// check all values of the queried dependency vulns
			for _, vuln := range updateVulns {
				assert.False(t, vuln.RiskRecalculatedAt.IsZero())
				assert.Equal(t, vuln.State, dtos.VulnStateFixed)
				assert.Equal(t, vuln.RawRiskAssessment, utils.Ptr(4.2))
				assert.Equal(t, vuln.RiskAssessment, utils.Ptr(5))

				assert.NotNil(t, vuln.TicketID)
				assert.NotNil(t, vuln.ComponentFixedVersion)
			}
		})
	})
}
