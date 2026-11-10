package tests

import (
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
)

func TestAttachGroupEvents(t *testing.T) {
	t.Run("only group events until cutoff limit should be applied", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

			vuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetVersionID: assetVersion.ID,
					AssetID:        asset.ID,
					State:          dtos.VulnStateOpen,
				},
				AssetVersionName:  assetVersion.Name,
				CVEID:             "CVE-1990-0001",
				VulnerabilityPath: []string{"root"},
			}
			assert.NoError(t, f.DB.Create(&vuln).Error)

			repo := repositories.NewDependencyVulnRepository(f.DB)

			sig := vuln.AssetSignature
			groupEvents := []models.VulnEvent{
				{
					AssetSignature: &sig,
					Type:           dtos.EventTypeDetected,
					UserID:         "system",
					CreatedAt:      time.Date(1990, time.March, 15, 13, 30, 0, 0, time.UTC),
				},
				{
					AssetSignature: &sig,
					Type:           dtos.EventTypeComment,
					UserID:         "system",
					CreatedAt:      time.Date(1990, time.March, 15, 14, 30, 0, 0, time.UTC),
				},
				{
					AssetSignature: &sig,
					Type:           dtos.EventTypeComment,
					UserID:         "system",
					CreatedAt:      time.Date(1990, time.March, 15, 15, 30, 0, 0, time.UTC),
				},
				{
					AssetSignature: &sig,
					Type:           dtos.EventTypeFixed,
					UserID:         "system",
					CreatedAt:      time.Date(1990, time.March, 15, 16, 30, 0, 0, time.UTC),
				},
			}
			for i := range groupEvents {
				assert.NoError(t, f.DB.Create(&groupEvents[i]).Error)
			}

			cutoff := time.Date(1990, time.March, 15, 15, 30, 0, 0, time.UTC)
			vulns := []models.DependencyVuln{vuln}
			err := repo.AttachGroupEvents(context.Background(), f.DB, vulns, &cutoff)
			assert.NoError(t, err)
			assert.Equal(t, 3, len(vulns[0].Events))
			assert.Equal(t, dtos.VulnStateOpen, vulns[0].State)
		})
	})
}

func TestLegacyArtifactNameFilter(t *testing.T) {
	t.Run("filtering by the artifact name of the join table should still only return the vulns of that artifact", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

			artifact1 := models.Artifact{ArtifactName: "artifact-1", AssetVersionID: assetVersion.ID, AssetID: asset.ID}
			artifact2 := models.Artifact{ArtifactName: "artifact-2", AssetVersionID: assetVersion.ID, AssetID: asset.ID}
			assert.NoError(t, f.DB.Create(&artifact1).Error)
			assert.NoError(t, f.DB.Create(&artifact2).Error)

			cve1 := models.CVE{CVE: "CVE-1990-0002"}
			cve2 := models.CVE{CVE: "CVE-1990-0003"}
			assert.NoError(t, f.DB.Create(&cve1).Error)
			assert.NoError(t, f.DB.Create(&cve2).Error)

			vuln1 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetVersionID: assetVersion.ID,
					AssetID:        asset.ID,
					State:          dtos.VulnStateOpen,
				},
				AssetVersionName:  assetVersion.Name,
				CVEID:             cve1.CVE,
				VulnerabilityPath: []string{"root"},
				Artifacts:         []models.Artifact{artifact1},
			}
			vuln2 := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetVersionID: assetVersion.ID,
					AssetID:        asset.ID,
					State:          dtos.VulnStateOpen,
				},
				AssetVersionName:  assetVersion.Name,
				CVEID:             cve2.CVE,
				VulnerabilityPath: []string{"root"},
				Artifacts:         []models.Artifact{artifact2},
			}
			assert.NoError(t, f.DB.Create(&vuln1).Error)
			assert.NoError(t, f.DB.Create(&vuln2).Error)

			repo := repositories.NewDependencyVulnRepository(f.DB)
			filter := []shared.FilterQuery{{Field: "artifact_dependency_vulns.artifact_artifact_name", Operator: "is", FieldValue: "artifact-1"}}

			paged, err := repo.GetDependencyVulnsByAssetVersionPagedAndFlat(context.Background(), nil, assetVersion.ID, shared.PageInfo{Page: 1, PageSize: 10}, "", filter, nil)
			assert.NoError(t, err)
			assert.Equal(t, int64(1), paged.Total)
			assert.Equal(t, vuln1.ID, paged.Data[0].ID)
		})
	})
}
