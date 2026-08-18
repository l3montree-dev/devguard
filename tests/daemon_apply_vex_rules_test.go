package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

// TestDaemonPipelineApplyVEXRulesAppliesExistingRuleToExistingVuln verifies the
// ApplyVEXRules pipeline stage: a VEX rule created after a vuln already existed
// (so scan-time application never saw them together) still gets applied to that
// vuln once the daemon pipeline runs again. There's deliberately no SBOM/VEX
// structure here - if there were, ScanAsset's own scan-time rule application
// would independently apply the same rule and the test wouldn't prove
// ApplyVEXRules specifically did anything.
func TestDaemonPipelineApplyVEXRulesAppliesExistingRuleToExistingVuln(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-apply-vex-rules")
		project := f.CreateProject(org.ID, "test-project-apply-vex-rules")
		asset := f.CreateAsset(project.ID, "test-asset-apply-vex-rules")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		cve := models.CVE{
			CVE:  "CVE-2025-TEST-APPLY-VEX",
			CVSS: 7.5,
		}
		err := f.DB.Create(&cve).Error
		assert.NoError(t, err)

		artifact := models.Artifact{
			ArtifactName:     "test-artifact",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		vulnerability := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateOpen,
				LastDetected:     time.Now().Add(-1 * time.Hour),
			},
			CVEID:             cve.CVE,
			ComponentPurl:     "pkg:npm/test-package@1.0.0",
			VulnerabilityPath: []string{"pkg:npm/test-package@1.0.0"},
			Artifacts:         []models.Artifact{artifact},
		}
		err = f.DB.Create(&vulnerability).Error
		assert.NoError(t, err)

		rule := models.VEXRule{
			AssetID:     asset.ID,
			CreatedByID: "test-user",
			Enabled:     true,
		}
		rule.VexSource = "manual"
		rule.Title = "accept this CVE"
		rule.Justification = "test justification"
		rule.EventType = dtos.EventTypeAccepted
		rule.SetCELExpression(fmt.Sprintf(`vuln.cveId == %q`, cve.CVE))
		err = f.DB.Create(&rule).Error
		assert.NoError(t, err)

		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err)

		var updatedVuln models.DependencyVuln
		err = f.DB.Preload("Events").First(&updatedVuln, "id = ?", vulnerability.ID).Error
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateAccepted, updatedVuln.State, "vuln should have been accepted by the VEX rule")

		var acceptEvent *models.VulnEvent
		for i := range updatedVuln.Events {
			if updatedVuln.Events[i].Type == dtos.EventTypeAccepted {
				acceptEvent = &updatedVuln.Events[i]
				break
			}
		}
		if assert.NotNil(t, acceptEvent, "should have an accepted event") {
			assert.True(t, acceptEvent.CreatedByVexRule, "accepted event should be attributed to the VEX rule")
			if assert.NotNil(t, acceptEvent.VexRuleID) {
				assert.Equal(t, rule.ID, *acceptEvent.VexRuleID)
			}
		}
	})
}

// TestDaemonPipelineApplyVEXRulesReopensAcceptedVuln verifies the reopen side:
// a reopen-type rule created after a vuln was already accepted still reopens it
// via ApplyVEXRules, without needing a fresh scan.
func TestDaemonPipelineApplyVEXRulesReopensAcceptedVuln(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-apply-vex-rules-reopen")
		project := f.CreateProject(org.ID, "test-project-apply-vex-rules-reopen")
		asset := f.CreateAsset(project.ID, "test-asset-apply-vex-rules-reopen")
		assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

		cve := models.CVE{
			CVE:  "CVE-2025-TEST-APPLY-VEX-REOPEN",
			CVSS: 7.5,
		}
		err := f.DB.Create(&cve).Error
		assert.NoError(t, err)

		artifact := models.Artifact{
			ArtifactName:     "test-artifact-reopen",
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		}
		err = f.DB.Create(&artifact).Error
		assert.NoError(t, err)

		vulnerability := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetID:          asset.ID,
				AssetVersionName: assetVersion.Name,
				State:            dtos.VulnStateAccepted,
				LastDetected:     time.Now().Add(-1 * time.Hour),
			},
			CVEID:             cve.CVE,
			ComponentPurl:     "pkg:npm/test-package-reopen@1.0.0",
			VulnerabilityPath: []string{"pkg:npm/test-package-reopen@1.0.0"},
			Artifacts:         []models.Artifact{artifact},
		}
		err = f.DB.Create(&vulnerability).Error
		assert.NoError(t, err)

		rule := models.VEXRule{
			AssetID:     asset.ID,
			CreatedByID: "test-user",
			Enabled:     true,
		}
		rule.VexSource = "manual"
		rule.Title = "reopen this CVE"
		rule.Justification = "test justification"
		rule.EventType = dtos.EventTypeReopened
		rule.SetCELExpression(fmt.Sprintf(`vuln.cveId == %q`, cve.CVE))
		err = f.DB.Create(&rule).Error
		assert.NoError(t, err)

		runner := f.CreateDaemonRunner()
		err = runner.RunDaemonPipelineForAsset(context.Background(), asset.ID)
		assert.NoError(t, err)

		var updatedVuln models.DependencyVuln
		err = f.DB.Preload("Events").First(&updatedVuln, "id = ?", vulnerability.ID).Error
		assert.NoError(t, err)
		assert.Equal(t, dtos.VulnStateOpen, updatedVuln.State, "vuln should have been reopened by the VEX rule")
	})
}
