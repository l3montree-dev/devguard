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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestArtifactRiskHistoryFromVulnStateIntervals(t *testing.T) {
	t.Parallel()
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	artifact := models.Artifact{
		ArtifactName:   "risk-history-artifact",
		AssetVersionID: assetVersion.ID,
		AssetID:        asset.ID,
	}
	require.NoError(t, db.Create(&artifact).Error)

	for _, cve := range []models.CVE{
		{CVE: "CVE-2026-70001", CVSS: 8.0, DatePublished: time.Now(), DateLastModified: time.Now()},
		{CVE: "CVE-2026-70002", CVSS: 3.0, DatePublished: time.Now(), DateLastModified: time.Now()},
	} {
		require.NoError(t, db.Create(&cve).Error)
	}

	createVuln := func(cveID, purl string, risk float64, path []string, fixedVersion *string) uuid.UUID {
		vuln := models.DependencyVuln{
			Vulnerability: models.Vulnerability{
				AssetVersionID: assetVersion.ID,
				State:          dtos.VulnStateOpen,
				AssetID:        asset.ID,
			},
			AssetVersionName:             assetVersion.Name,
			CVEID:                        cveID,
			ComponentPurl:                purl,
			RiskAssessment:               &risk,
			VulnerabilityPath:            path,
			DirectDependencyFixedVersion: fixedVersion,
		}
		require.NoError(t, db.Create(&vuln).Error)
		return vuln.ID
	}
	// a and c share cve and purl, so they count once in the cve + purl distribution
	a := createVuln("CVE-2026-70001", "pkg:npm/a@1.0.0", 8, []string{"pkg:npm/a@1.0.0"}, new("1.0.1"))
	b := createVuln("CVE-2026-70002", "pkg:npm/b@1.0.0", 3, []string{"pkg:npm/b@1.0.0"}, nil)
	c := createVuln("CVE-2026-70001", "pkg:npm/a@1.0.0", 8, []string{"pkg:npm/x@1.0.0", "pkg:npm/a@1.0.0"}, nil)

	today := time.Now().UTC().Truncate(24 * time.Hour)
	day := func(i int) time.Time { return today.AddDate(0, 0, i-10) }
	event := func(vulnID uuid.UUID, eventType dtos.VulnEventType, onDay int, artifactID *uuid.UUID) {
		require.NoError(t, db.Create(&models.VulnEvent{
			CreatedAt:        day(onDay).Add(12 * time.Hour),
			Type:             eventType,
			DependencyVulnID: new(vulnID),
			ArtifactID:       artifactID,
			UserID:           "system",
		}).Error)
	}

	event(a, dtos.EventTypeDetected, 0, nil)
	event(a, dtos.EventTypeDetectedInArtifact, 0, &artifact.ID)
	event(c, dtos.EventTypeDetected, 0, nil)
	event(c, dtos.EventTypeDetectedInArtifact, 0, &artifact.ID)
	event(b, dtos.EventTypeDetected, 1, nil)
	event(b, dtos.EventTypeDetectedInArtifact, 1, &artifact.ID)
	event(a, dtos.EventTypeFixed, 2, nil)
	// b stays open in the asset version but is no longer part of the artifact
	event(b, dtos.EventTypeFixedInArtifact, 3, &artifact.ID)
	// a scan does not reopen an accepted vuln, so this detected event must not count
	event(b, dtos.EventTypeAccepted, 4, nil)
	event(b, dtos.EventTypeDetected, 5, nil)
	event(b, dtos.EventTypeReopened, 6, nil)
	event(a, dtos.EventTypeReopened, 5, nil)

	repo := repositories.NewArtifactRiskHistoryRepository(db)
	ctx := context.Background()
	require.NoError(t, repo.RecalculateForAsset(ctx, nil, asset.ID))

	start := day(-2)
	history, err := repo.GetRiskHistory(ctx, nil, &artifact.ID, assetVersion.ID, start, today)
	require.NoError(t, err)
	require.Len(t, history, 13)
	at := func(h []models.ArtifactRiskHistory, i int) models.ArtifactRiskHistory {
		row := h[i+2]
		require.True(t, day(i).Equal(row.Day.UTC()), "day %d: got %s", i, row.Day)
		return row
	}

	t.Run("artifact scope", func(t *testing.T) {
		for i := -2; i < 0; i++ {
			assert.Equal(t, 0, at(history, i).OpenDependencyVulns)
			assert.Equal(t, 0, at(history, i).FixedDependencyVulns)
		}

		d0 := at(history, 0)
		assert.Equal(t, 2, d0.OpenDependencyVulns)
		assert.Equal(t, 0, d0.FixedDependencyVulns)
		assert.Equal(t, 2, d0.High)
		assert.Equal(t, 2, d0.HighCVSS)
		assert.Equal(t, 1, d0.FixableHigh)
		assert.Equal(t, 1, d0.CVEPurlHigh)
		assert.Equal(t, 1, d0.CVEPurlFixableHigh)
		assert.Equal(t, artifact.ArtifactName, d0.ArtifactName)

		d1 := at(history, 1)
		assert.Equal(t, 3, d1.OpenDependencyVulns)
		assert.Equal(t, 1, d1.Low)
		assert.Equal(t, 1, d1.LowCVSS)
		assert.Equal(t, 2, d1.High)
		assert.Equal(t, 1, d1.CVEPurlLow)
		assert.Equal(t, 1, d1.CVEPurlHigh)
		assert.InDelta(t, 19.0, d1.SumOpenRisk, 0.0001)

		d2 := at(history, 2)
		assert.Equal(t, 2, d2.OpenDependencyVulns)
		assert.Equal(t, 1, d2.FixedDependencyVulns)
		assert.Equal(t, 1, d2.High)
		assert.Equal(t, 0, d2.FixableHigh)
		assert.Equal(t, 1, d2.CVEPurlHigh)
		assert.Equal(t, 0, d2.CVEPurlFixableHigh)

		// b left the artifact, so it no longer counts as open even though it is still open in the asset version
		for i := 3; i <= 4; i++ {
			row := at(history, i)
			assert.Equal(t, 1, row.OpenDependencyVulns)
			assert.Equal(t, 2, row.FixedDependencyVulns)
			assert.InDelta(t, 8.0, row.SumOpenRisk, 0.0001)
			assert.InDelta(t, 11.0, row.SumClosedRisk, 0.0001)
			assert.InDelta(t, 5.5, row.AvgClosedRisk, 0.0001)
		}

		// reopening b does not bring it back into the artifact
		for i := 5; i <= 10; i++ {
			row := at(history, i)
			assert.Equal(t, 2, row.OpenDependencyVulns)
			assert.Equal(t, 1, row.FixedDependencyVulns)
			assert.Equal(t, 2, row.High)
			assert.Equal(t, 1, row.FixableHigh)
			assert.Equal(t, 1, row.CVEPurlHigh)
		}

		latest, err := repo.GetLatestRiskHistory(ctx, nil, &artifact.ID, assetVersion.ID)
		require.NoError(t, err)
		require.NotNil(t, latest)
		assert.Equal(t, 2, latest.OpenDependencyVulns)
		assert.Equal(t, 1, latest.FixedDependencyVulns)
	})

	t.Run("asset version scope", func(t *testing.T) {
		history, err := repo.GetRiskHistory(ctx, nil, nil, assetVersion.ID, start, today)
		require.NoError(t, err)
		require.Len(t, history, 13)

		assert.Equal(t, 3, at(history, 1).OpenDependencyVulns)
		assert.Equal(t, 2, at(history, 3).OpenDependencyVulns)
		assert.Equal(t, 1, at(history, 3).FixedDependencyVulns)
		assert.Equal(t, 1, at(history, 4).OpenDependencyVulns)
		assert.Equal(t, 2, at(history, 4).FixedDependencyVulns)
		// b was accepted, the detected event of day 5 does not reopen it
		assert.Equal(t, 2, at(history, 5).OpenDependencyVulns)
		assert.Equal(t, 1, at(history, 5).FixedDependencyVulns)
		for i := 6; i <= 10; i++ {
			assert.Equal(t, 3, at(history, i).OpenDependencyVulns)
			assert.Equal(t, 0, at(history, i).FixedDependencyVulns)
		}
	})

	t.Run("recalculating replaces the intervals", func(t *testing.T) {
		event(c, dtos.EventTypeFalsePositive, 7, nil)
		require.NoError(t, repo.RecalculateForAsset(ctx, nil, asset.ID))

		history, err := repo.GetRiskHistory(ctx, nil, &artifact.ID, assetVersion.ID, start, today)
		require.NoError(t, err)
		assert.Equal(t, 2, at(history, 6).OpenDependencyVulns)
		assert.Equal(t, 1, at(history, 7).OpenDependencyVulns)
		assert.Equal(t, 2, at(history, 7).FixedDependencyVulns)
	})
}
