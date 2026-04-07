// Copyright (C) 2026 l3montree GmbH
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
	"context"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAverageRemediationTimesForRelease_ReopenCycle verifies that when a vuln is
// detected→fixed→reopened→fixed, each fix is measured from its preceding open event.
// Concretely: both cycles are 1h, so the average must be 3600s — not 7200s
// (which would happen if the second fix were measured from the original detection).
func TestAverageRemediationTimesForRelease_ReopenCycle(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, project, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	cve := models.CVE{
		CVE:              "CVE-2026-88888",
		CVSS:             8.0,
		Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		DatePublished:    time.Now(),
		DateLastModified: time.Now(),
	}
	require.NoError(t, db.Create(&cve).Error)

	risk := 8.0
	depVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			State:            dtos.VulnStateOpen,
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		},
		CVEID:             cve.CVE,
		ComponentPurl:     "pkg:npm/reopen-test@1.0.0",
		RawRiskAssessment: &risk,
	}
	require.NoError(t, db.Create(&depVuln).Error)
	vulnID := depVuln.ID // set by BeforeSave hook after Create

	// Timeline: detected(T1) → fixed(T1+1h) → reopened(T1+3h) → fixed(T1+4h)
	// Cycle 1: fixed_at - detected_at = 1h = 3600s
	// Cycle 2: fixed2_at - reopened_at = 1h = 3600s
	// Average = 3600s (not 7200s which would indicate measuring from T1 again)
	t1 := time.Now().Add(-4 * time.Hour)
	require.NoError(t, db.Create(&models.VulnEvent{
		CreatedAt:        t1,
		Type:             dtos.EventTypeDetected,
		DependencyVulnID: utils.Ptr(vulnID),
	}).Error)
	require.NoError(t, db.Create(&models.VulnEvent{
		CreatedAt:        t1.Add(time.Hour),
		Type:             dtos.EventTypeFixed,
		DependencyVulnID: utils.Ptr(vulnID),
	}).Error)
	require.NoError(t, db.Create(&models.VulnEvent{
		CreatedAt:        t1.Add(3 * time.Hour),
		Type:             dtos.EventTypeReopened,
		DependencyVulnID: utils.Ptr(vulnID),
	}).Error)
	require.NoError(t, db.Create(&models.VulnEvent{
		CreatedAt:        t1.Add(4 * time.Hour),
		Type:             dtos.EventTypeFixed,
		DependencyVulnID: utils.Ptr(vulnID),
	}).Error)

	artifactName := "reopen-artifact"
	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}
	require.NoError(t, db.Create(&artifact).Error)

	release := models.Release{
		Name:      "v2.0.0",
		ProjectID: project.ID,
	}
	require.NoError(t, db.Create(&release).Error)

	releaseItem := models.ReleaseItem{
		ReleaseID:        release.ID,
		ArtifactName:     &artifactName,
		AssetVersionName: &assetVersion.Name,
		AssetID:          &asset.ID,
	}
	require.NoError(t, db.Create(&releaseItem).Error)

	repo := repositories.NewStatisticsRepository(db)
	result, err := repo.AverageRemediationTimesForRelease(context.Background(), nil, release.ID)

	require.NoError(t, err)

	// Both cycles are 1h each → average must be 3600s, not 7200s
	assert.InDelta(t, 3600.0, result.RiskAvgHigh, 5.0, "risk avg high should be ~3600s (both cycles 1h each)")
	assert.InDelta(t, 3600.0, result.CVSSAvgHigh, 5.0, "cvss avg high should be ~3600s (both cycles 1h each)")

	assert.Equal(t, 0.0, result.RiskAvgLow)
	assert.Equal(t, 0.0, result.RiskAvgMedium)
	assert.Equal(t, 0.0, result.RiskAvgCritical)
	assert.Equal(t, 0.0, result.CVSSAvgLow)
	assert.Equal(t, 0.0, result.CVSSAvgMedium)
	assert.Equal(t, 0.0, result.CVSSAvgCritical)
}

func TestAverageRemediationTimesForRelease(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, project, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	// Create a CVE with CVSS 8.0 (high band: 7-9)
	cve := models.CVE{
		CVE:              "CVE-2026-99999",
		CVSS:             8.0,
		Vector:           "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
		DatePublished:    time.Now(),
		DateLastModified: time.Now(),
	}
	require.NoError(t, db.Create(&cve).Error)

	risk := 8.0
	depVuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			State:            dtos.VulnStateFixed,
			AssetVersionName: assetVersion.Name,
			AssetID:          asset.ID,
		},
		CVEID:             cve.CVE,
		ComponentPurl:     "pkg:npm/test-pkg@1.0.0",
		RawRiskAssessment: &risk,
	}
	require.NoError(t, db.Create(&depVuln).Error)
	// ID is set by BeforeSave hook (hash of CVEID+AssetVersionName+AssetID+path)
	vulnID := depVuln.ID

	// Two events: detected → fixed 1h later. Fixing time = 3600s.
	detectedAt := time.Now().Add(-2 * time.Hour)
	fixedAt := detectedAt.Add(time.Hour)

	require.NoError(t, db.Create(&models.VulnEvent{
		CreatedAt:        detectedAt,
		Type:             dtos.EventTypeDetected,
		DependencyVulnID: utils.Ptr(vulnID),
	}).Error)
	require.NoError(t, db.Create(&models.VulnEvent{
		CreatedAt:        fixedAt,
		Type:             dtos.EventTypeFixed,
		DependencyVulnID: utils.Ptr(vulnID),
	}).Error)

	// Create an artifact so the release item satisfies the chk_one_not_null constraint
	artifactName := "test-artifact"
	artifact := models.Artifact{
		ArtifactName:     artifactName,
		AssetVersionName: assetVersion.Name,
		AssetID:          asset.ID,
	}
	require.NoError(t, db.Create(&artifact).Error)

	// Create release and link it to the artifact (which in turn links to the asset version)
	release := models.Release{
		Name:      "v1.0.0",
		ProjectID: project.ID,
	}
	require.NoError(t, db.Create(&release).Error)

	releaseItem := models.ReleaseItem{
		ReleaseID:        release.ID,
		ArtifactName:     &artifactName,
		AssetVersionName: &assetVersion.Name,
		AssetID:          &asset.ID,
	}
	require.NoError(t, db.Create(&releaseItem).Error)

	repo := repositories.NewStatisticsRepository(db)
	result, err := repo.AverageRemediationTimesForRelease(context.Background(), nil, release.ID)

	require.NoError(t, err)

	// Fixing time should be ~3600s in the high risk/CVSS band
	assert.InDelta(t, 3600.0, result.RiskAvgHigh, 5.0, "risk avg high should be ~3600s")
	assert.InDelta(t, 3600.0, result.CVSSAvgHigh, 5.0, "cvss avg high should be ~3600s")

	// All other bands should be zero
	assert.Equal(t, 0.0, result.RiskAvgLow)
	assert.Equal(t, 0.0, result.RiskAvgMedium)
	assert.Equal(t, 0.0, result.RiskAvgCritical)
	assert.Equal(t, 0.0, result.CVSSAvgLow)
	assert.Equal(t, 0.0, result.CVSSAvgMedium)
	assert.Equal(t, 0.0, result.CVSSAvgCritical)
}
