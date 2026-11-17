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

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/statemachine"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyVulnArtifactLinkEvents(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		ctx := context.Background()
		_, _, asset, assetVersion := f.CreateOrgProjectAssetAndVersion()

		cve := models.CVE{CVE: "CVE-2026-0001", CVSS: 7.5, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"}
		require.NoError(t, f.DB.Create(&cve).Error)

		artifact1 := models.Artifact{ArtifactName: "artifact-1", AssetVersionID: assetVersion.ID, AssetID: asset.ID}
		artifact2 := models.Artifact{ArtifactName: "artifact-2", AssetVersionID: assetVersion.ID, AssetID: asset.ID}
		require.NoError(t, f.DB.Create(&artifact1).Error)
		require.NoError(t, f.DB.Create(&artifact2).Error)

		linkEvents := func(t *testing.T, vulnID uuid.UUID) []models.VulnEvent {
			var events []models.VulnEvent
			require.NoError(t, f.DB.Where("dependency_vuln_id = ? AND type IN ?", vulnID, []dtos.VulnEventType{dtos.EventTypeDetectedInArtifact, dtos.EventTypeFixedInArtifact}).Order("created_at ASC").Find(&events).Error)
			return events
		}

		newVuln := func(purl string, artifacts ...models.Artifact) models.DependencyVuln {
			return models.DependencyVuln{
				Vulnerability:     models.Vulnerability{AssetVersionID: assetVersion.ID, AssetID: asset.ID},
				AssetVersionName:  assetVersion.Name,
				CVEID:             cve.CVE,
				CVE:               &cve,
				ComponentPurl:     purl,
				VulnerabilityPath: []string{purl},
				Artifacts:         artifacts,
			}
		}

		t.Run("detecting a new vuln emits one detectedInArtifact event per artifact", func(t *testing.T) {
			vuln := newVuln("pkg:npm/a@1.0.0", artifact1, artifact2)
			require.NoError(t, f.App.DependencyVulnService.UserDetectedDependencyVulns(ctx, f.DB, "user", nil, []models.DependencyVuln{vuln}, assetVersion, asset))

			events := linkEvents(t, vuln.CalculateHash())
			require.Len(t, events, 2)
			artifactIDs := []uuid.UUID{*events[0].ArtifactID, *events[1].ArtifactID}
			assert.ElementsMatch(t, []uuid.UUID{artifact1.ID, artifact2.ID}, artifactIDs)
			for _, ev := range events {
				assert.Equal(t, dtos.EventTypeDetectedInArtifact, ev.Type)
			}
		})

		t.Run("linking and unlinking an existing vuln emits events only for real link changes", func(t *testing.T) {
			vuln := newVuln("pkg:npm/b@1.0.0", artifact1)
			require.NoError(t, f.App.DependencyVulnService.UserDetectedDependencyVulns(ctx, f.DB, "user", nil, []models.DependencyVuln{vuln}, assetVersion, asset))
			require.Len(t, linkEvents(t, vuln.CalculateHash()), 1)

			// the preloaded artifacts are stale - the link to artifact 1 already exists
			stale := vuln
			stale.Artifacts = nil
			require.NoError(t, f.App.DependencyVulnService.UserDetectedDependencyVulnInAnotherArtifact(ctx, f.DB, []models.DependencyVuln{stale}, artifact1))
			require.Len(t, linkEvents(t, vuln.CalculateHash()), 1)

			vuln.Artifacts = []models.Artifact{artifact1}
			require.NoError(t, f.App.DependencyVulnService.UserDetectedDependencyVulnInAnotherArtifact(ctx, f.DB, []models.DependencyVuln{vuln}, artifact2))
			events := linkEvents(t, vuln.CalculateHash())
			require.Len(t, events, 2)
			assert.Equal(t, dtos.EventTypeDetectedInArtifact, events[1].Type)
			assert.Equal(t, artifact2.ID, *events[1].ArtifactID)

			require.NoError(t, f.App.DependencyVulnService.UserDidNotDetectDependencyVulnInArtifactAnymore(ctx, f.DB, []models.DependencyVuln{vuln}, artifact2))
			events = linkEvents(t, vuln.CalculateHash())
			require.Len(t, events, 3)
			assert.Equal(t, dtos.EventTypeFixedInArtifact, events[2].Type)
			assert.Equal(t, artifact2.ID, *events[2].ArtifactID)

			// the link is already gone
			require.NoError(t, f.App.DependencyVulnService.UserDidNotDetectDependencyVulnInArtifactAnymore(ctx, f.DB, []models.DependencyVuln{vuln}, artifact2))
			assert.Len(t, linkEvents(t, vuln.CalculateHash()), 3)

			var stored models.DependencyVuln
			require.NoError(t, f.DB.First(&stored, "id = ?", vuln.CalculateHash()).Error)
			assert.Equal(t, dtos.VulnStateOpen, stored.State)
		})

		t.Run("a vuln copied from another branch gets link events for its own artifacts only", func(t *testing.T) {
			otherVersion := f.CreateAssetVersion(asset.ID, "feature", false)
			otherArtifact := models.Artifact{ArtifactName: "artifact-1", AssetVersionID: otherVersion.ID, AssetID: asset.ID}
			require.NoError(t, f.DB.Create(&otherArtifact).Error)

			mainVuln := newVuln("pkg:npm/c@1.0.0", artifact1)
			require.NoError(t, f.App.DependencyVulnService.UserDetectedDependencyVulns(ctx, f.DB, "user", nil, []models.DependencyVuln{mainVuln}, assetVersion, asset))
			require.NoError(t, f.DB.Preload("Events").First(&mainVuln, "id = ?", mainVuln.CalculateHash()).Error)

			featureVuln := models.DependencyVuln{
				Vulnerability:     models.Vulnerability{AssetVersionID: otherVersion.ID, AssetID: asset.ID},
				AssetVersionName:  otherVersion.Name,
				CVEID:             cve.CVE,
				ComponentPurl:     "pkg:npm/c@1.0.0",
				VulnerabilityPath: []string{"pkg:npm/c@1.0.0"},
				Artifacts:         []models.Artifact{otherArtifact},
			}
			diff := statemachine.DiffVulnsBetweenBranches([]*models.DependencyVuln{&featureVuln}, []*models.DependencyVuln{&mainVuln})
			require.Len(t, diff.ExistingOnOtherBranches, 1)
			require.NoError(t, f.App.DependencyVulnService.UserDetectedExistingVulnOnDifferentBranch(ctx, f.DB, diff.ExistingOnOtherBranches, otherVersion, asset))

			events := linkEvents(t, featureVuln.CalculateHash())
			require.Len(t, events, 1)
			assert.Equal(t, otherArtifact.ID, *events[0].ArtifactID)
		})
	})
}
