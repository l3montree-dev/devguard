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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestVEXRuleCreatedOnFeatureBranchClosesVulnOnDefaultBranch(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		app := echo.New()
		userSession := NewUserSession(t, "reporter")
		setupCtx := func(ctx shared.Context) {
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, userSession)
		}

		const defaultBranch = "main"
		const featureBranch = "feature/opa-not-used"

		scan := func(artifactName, branch string) {
			t.Helper()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbomWithVulnerability())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", artifactName)
			req.Header.Set("X-Asset-Default-Branch", defaultBranch)
			req.Header.Set("X-Asset-Ref", branch)
			req.Header.Set("X-Origin", "test-origin")
			recorder := httptest.NewRecorder()
			ctx := app.NewContext(req, recorder)
			setupCtx(ctx)
			assert.NoError(t, f.App.ScanController.ScanDependencyVulnFromProject(ctx))
			assert.Equal(t, 200, recorder.Code, recorder.Body.String())
		}

		fetchVuln := func(branch string) models.DependencyVuln {
			t.Helper()
			var vulns []models.DependencyVuln
			assert.NoError(t, f.DB.Preload("Events").Where(
				"asset_id = ? AND asset_version_name = ? AND cve_id = ?",
				asset.ID, branch, "CVE-2025-46569",
			).Find(&vulns).Error)
			assert.Len(t, vulns, 1, "expected exactly one CVE-2025-46569 vuln on branch %q", branch)
			return vulns[0]
		}

		scan("backend-amd64", defaultBranch)
		assert.Equal(t, dtos.VulnStateOpen, fetchVuln(defaultBranch).State)

		path := fetchVuln(defaultBranch).VulnerabilityPath
		celExpression := vexrules.ToCELExpression("CVE-2025-46569",
			vexrules.PathPattern(append([]string{"ROOT"}, path...)))

		body, err := json.Marshal(dtos.CreateVEXRuleRequest{
			Title:                   "opa is not reachable from our code",
			Justification:           "vendored dependency, code path never executes",
			MechanicalJustification: dtos.VulnerableCodeNotInExecutePath,
			CELExpression:           celExpression,
			EventType:               dtos.EventTypeFalsePositive,
		})
		assert.NoError(t, err)

		createReq := httptest.NewRequest("POST", "/vex-rules", strings.NewReader(string(body)))
		createReq.Header.Set("Content-Type", "application/json")
		createRecorder := httptest.NewRecorder()
		createCtx := app.NewContext(createReq, createRecorder)
		setupCtx(createCtx)
		assert.NoError(t, f.App.VEXRuleController.Create(createCtx))
		assert.Equal(t, 201, createRecorder.Code, createRecorder.Body.String())

		scan("backend-amd64-feature", featureBranch)
		v := fetchVuln(featureBranch)
		assert.Equal(t, dtos.VulnStateFalsePositive, v.State)

		var rule dtos.VEXRuleDTO
		assert.NoError(t, json.Unmarshal(createRecorder.Body.Bytes(), &rule))
		assert.NotEmpty(t, rule.ID)

		assert.Equal(t, dtos.VulnStateFalsePositive, fetchVuln(featureBranch).State,
			"vuln on the branch the rule was created from must be closed")
		assert.Equal(t, dtos.VulnStateFalsePositive, fetchVuln(defaultBranch).State,
			"identical vuln on the default branch must be closed too, with no scan or race involved")
	})
}
