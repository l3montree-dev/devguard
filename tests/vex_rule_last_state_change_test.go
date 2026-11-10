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
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Group events change the state of every vuln sharing an asset signature with a
// raw UPDATE, bypassing Vulnerability.SetState - last_state_change must still move.
func TestApplyGroupEventsAndSaveUpdatesLastStateChange(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		vuln, staleStateChange := createVulnWithStaleStateChange(t, f, "group-events-bulk")

		before := time.Now()
		_, err := f.App.DependencyVulnRepository.ApplyGroupEventsAndSave(context.Background(), f.DB, []models.VulnEvent{
			acceptGroupEvent(vuln.AssetSignature),
		})
		require.NoError(t, err)

		var updated models.DependencyVuln
		require.NoError(t, f.DB.Where("id = ?", vuln.ID).First(&updated).Error)

		assert.Equal(t, dtos.VulnStateAccepted, updated.State)
		assert.NotEqual(t, staleStateChange.UTC(), updated.LastStateChange.UTC(), "last_state_change was not updated")
		assert.False(t, updated.LastStateChange.Before(before.Add(-time.Second)), "last_state_change should be set to the time of the state change")
	})
}

func createVulnWithStaleStateChange(t *testing.T, f *TestFixture, name string) (models.DependencyVuln, time.Time) {
	t.Helper()
	org := f.CreateOrg("test-org-" + name)
	project := f.CreateProject(org.ID, "test-project-"+name)
	asset := f.CreateAsset(project.ID, "test-asset-"+name)
	assetVersion := f.CreateAssetVersion(asset.ID, "main", true)

	cve := models.CVE{CVE: "CVE-2025-TEST-" + name, CVSS: 7.5}
	require.NoError(t, f.DB.Create(&cve).Error)

	artifact := models.Artifact{
		ArtifactName:   "artifact-" + name,
		AssetVersionID: assetVersion.ID,
		AssetID:        asset.ID,
	}
	require.NoError(t, f.DB.Create(&artifact).Error)

	vuln := models.DependencyVuln{
		Vulnerability: models.Vulnerability{
			AssetID:         asset.ID,
			AssetVersionID:  assetVersion.ID,
			State:           dtos.VulnStateOpen,
			LastStateChange: time.Now().Add(-24 * time.Hour),
		},
		CVEID:             cve.CVE,
		ComponentPurl:     "pkg:npm/" + name + "@1.0.0",
		VulnerabilityPath: []string{"pkg:npm/" + name + "@1.0.0"},
		Artifacts:         []models.Artifact{artifact},
	}
	require.NoError(t, f.DB.Create(&vuln).Error)

	var stored models.DependencyVuln
	require.NoError(t, f.DB.Where("id = ?", vuln.ID).First(&stored).Error)
	require.NotZero(t, stored.AssetSignature)
	return stored, stored.LastStateChange
}

func acceptGroupEvent(assetSignature int64) models.VulnEvent {
	justification := "accepted by group event"
	return models.VulnEvent{
		Type:           dtos.EventTypeAccepted,
		UserID:         "test-user",
		Justification:  &justification,
		AssetSignature: &assetSignature,
	}
}
