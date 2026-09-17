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
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVEXRuleGroupEventLeavesVulnsWithoutOwnEvent reproduces how a vuln ends up in a
// state that nothing in its own event history accounts for.
//
// VEXRuleController.Create does not write one event per affected vuln. It writes a
// single "group" event per asset signature (dependency_vuln_id NULL, asset_signature
// set) and then changes every matching vuln's state with one raw UPDATE, in
// ApplyGroupEventsAndSave. Nothing ever expands those group events onto the vulns
// they closed, so from any individual vuln's perspective the state changed on its own.
func TestVEXRuleGroupEventLeavesVulnsWithoutOwnEvent(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("test-org-group-event")
		project := f.CreateProject(org.ID, "test-project-group-event")
		asset := f.CreateAsset(project.ID, "test-asset-group-event")
		mainVersion := f.CreateAssetVersion(asset.ID, "main", true)
		tagVersion := f.CreateAssetVersion(asset.ID, "v1.0.0", false)

		cve := models.CVE{CVE: "CVE-2025-TEST-GROUP-EVENT", CVSS: 7.5}
		require.NoError(t, f.DB.Create(&cve).Error)

		// the same vulnerability on two asset versions - same CVE, same component,
		// same path, so both rows share one asset_signature
		createVuln := func(versionName string) models.DependencyVuln {
			t.Helper()
			artifact := models.Artifact{
				ArtifactName:     "artifact-" + versionName,
				AssetVersionName: versionName,
				AssetID:          asset.ID,
			}
			require.NoError(t, f.DB.Create(&artifact).Error)

			vuln := models.DependencyVuln{
				Vulnerability: models.Vulnerability{
					AssetID:          asset.ID,
					AssetVersionName: versionName,
					State:            dtos.VulnStateOpen,
					LastStateChange:  time.Now().Add(-1 * time.Hour),
				},
				CVEID:             cve.CVE,
				ComponentPurl:     "pkg:npm/group-event-package@1.0.0",
				VulnerabilityPath: []string{"pkg:npm/group-event-package@1.0.0"},
				Artifacts:         []models.Artifact{artifact},
			}
			require.NoError(t, f.DB.Create(&vuln).Error)
			return vuln
		}

		mainVuln := createVuln(mainVersion.Name)
		tagVuln := createVuln(tagVersion.Name)

		reload := func(id string) models.DependencyVuln {
			t.Helper()
			var v models.DependencyVuln
			require.NoError(t, f.DB.Preload("Events").Where("id = ?", id).First(&v).Error)
			return v
		}

		require.Equal(t, reload(mainVuln.ID.String()).AssetSignature, reload(tagVuln.ID.String()).AssetSignature,
			"both vulns must share an asset signature for the group path to be exercised")

		stateChangeBefore := reload(tagVuln.ID.String()).LastStateChange

		// create the rule through the controller - the same path a user takes in the UI
		app := echo.New()
		body, err := json.Marshal(dtos.CreateVEXRuleRequest{
			Title:                   "not exploitable",
			Justification:           "only used during testing",
			MechanicalJustification: dtos.ComponentNotPresent,
			CELExpression:           fmt.Sprintf(`vuln.cveId == %q`, cve.CVE),
			EventType:               dtos.EventTypeFalsePositive,
		})
		require.NoError(t, err)

		req := httptest.NewRequest("POST", "/vex-rules", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		ctx := app.NewContext(req, recorder)
		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, project)
		shared.SetOrg(ctx, org)
		shared.SetSession(ctx, NewUserSession(t, "reporter"))
		require.NoError(t, f.App.VEXRuleController.Create(ctx))
		require.Equal(t, 201, recorder.Code, recorder.Body.String())

		// the rule closed both vulns
		updatedMain := reload(mainVuln.ID.String())
		updatedTag := reload(tagVuln.ID.String())
		assert.Equal(t, dtos.VulnStateFalsePositive, updatedMain.State)
		assert.Equal(t, dtos.VulnStateFalsePositive, updatedTag.State)

		// ...but the group event was written against the signature, not the vulns, so
		// neither of them has an event that accounts for the state it is now in
		var groupEvents []models.VulnEvent
		require.NoError(t, f.DB.Where(
			"dependency_vuln_id IS NULL AND asset_signature = ?", updatedTag.AssetSignature,
		).Find(&groupEvents).Error)
		assert.Len(t, groupEvents, 1, "exactly one group event is written for the signature")

		for _, v := range []models.DependencyVuln{updatedMain, updatedTag} {
			assert.Empty(t, v.Events,
				"vuln %s on %s is falsePositive but has no event of its own explaining it",
				v.ID, v.AssetVersionName)
		}

		// and the raw UPDATE never touches last_state_change, so the timestamp still
		// points at a moment before the state actually changed
		assert.Equal(t, stateChangeBefore.UTC(), updatedTag.LastStateChange.UTC(),
			"last_state_change is left stale by the group UPDATE")
	})
}
