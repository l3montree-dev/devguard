package tests

import (
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
)

func TestAttachGroupEvents(t *testing.T) {
	t.Run("only group events until cutoff limit should be applied", func(t *testing.T) {
		WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
			_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

			vuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: assetVersion.Name,
					State:            dtos.VulnStateOpen,
				},
				CVEID:             "CVE-1990-0001",
				VulnerabilityPath: []string{"root"},
			}
			assert.NoError(t, f.DB.Create(&vuln).Error)

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
			err := repositories.AttachGroupEvents(f.DB, vulns, &cutoff)
			assert.NoError(t, err)
			assert.Equal(t, 3, len(vulns[0].Events))
			assert.Equal(t, dtos.VulnStateOpen, vulns[0].State)
		})
	})
}
