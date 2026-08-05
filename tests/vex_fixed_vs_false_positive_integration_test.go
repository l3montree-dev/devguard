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
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/vexrules"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// TestVEXFixedOnDefaultBranchButFalsePositiveOnBranchX covers the case where a
// vulnerability is fixed on the default branch, but branch X still has the
// vulnerable component and its vuln has been marked false positive there.
// The VEX export for branch X must keep reporting false positive - it must
// not be overridden just because the default branch resolved it.
func TestVEXFixedOnDefaultBranchButFalsePositiveOnBranchX(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		const defaultBranch = "main"
		const branchX = "branch-x"

		app := echo.New()
		setupCtx := func(ctx shared.Context) {
			shared.SetAsset(ctx, asset)
			shared.SetProject(ctx, project)
			shared.SetOrg(ctx, org)
			shared.SetSession(ctx, NewUserSession(t, "reporter"))
		}

		scan := func(ref string, sbom func() io.Reader) {
			t.Helper()
			req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", sbom())
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Artifact-Name", "backend")
			req.Header.Set("X-Asset-Default-Branch", defaultBranch)
			req.Header.Set("X-Asset-Ref", ref)
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
			assert.NoError(t, f.DB.Where(
				"asset_id = ? AND asset_version_name = ? AND cve_id = ?", asset.ID, branch, "CVE-2025-46569",
			).Find(&vulns).Error)
			assert.Len(t, vulns, 1, "expected exactly one CVE-2025-46569 vuln on branch %q", branch)
			return vulns[0]
		}

		// both branches see the vulnerability
		scan(defaultBranch, sbomWithVulnerability)
		scan(branchX, sbomWithVulnerability)

		// fix it on the default branch - by rescanning without the vulnerable component
		scan(defaultBranch, sbomWithoutVulnerability)
		assert.Equal(t, dtos.VulnStateFixed, fetchVuln(defaultBranch).State)

		// mark it false positive on branch X, via a VEX rule (same mechanism a user would use)
		path := fetchVuln(branchX).VulnerabilityPath
		celExpression := vexrules.ToCELExpression("CVE-2025-46569",
			vexrules.PathPattern(append([]string{"ROOT"}, path...)))

		body, err := json.Marshal(dtos.CreateVEXRuleRequest{
			Title:                   "not applicable to branch-x",
			Justification:           "does not apply here",
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

		branchXVersion := fetchVuln(branchX).AssetVersionName
		var assetVersion models.AssetVersion
		assert.NoError(t, f.DB.Where("asset_id = ? AND name = ?", asset.ID, branchXVersion).First(&assetVersion).Error)

		// export the VEX for branch X and assert the vuln is reported as false positive
		req := httptest.NewRequest("GET", "/vex.json/", nil)
		recorder := httptest.NewRecorder()
		ctx := app.NewContext(req, recorder)
		setupCtx(ctx)
		shared.SetAssetVersion(ctx, assetVersion)
		shared.SetArtifact(ctx, models.Artifact{ArtifactName: "backend", AssetVersionName: assetVersion.Name, AssetID: asset.ID})

		assert.NoError(t, f.App.ArtifactController.CycloneDXVexJSON(ctx))
		assert.Equal(t, 200, recorder.Code, recorder.Body.String())

		respBody, err := io.ReadAll(recorder.Result().Body)
		assert.NoError(t, err)
		var bom cdx.BOM
		assert.NoError(t, json.Unmarshal(respBody, &bom))

		var vuln *cdx.Vulnerability
		for i := range *bom.Vulnerabilities {
			if (*bom.Vulnerabilities)[i].ID == "CVE-2025-46569" {
				vuln = &(*bom.Vulnerabilities)[i]
				break
			}
		}
		assert.NotNil(t, vuln, "CVE-2025-46569 should be present in branch X's exported VEX")
		assert.Equal(t, cdx.IASFalsePositive, vuln.Analysis.State,
			"branch X's vuln was explicitly marked false positive - the default branch being fixed must not override that in the VEX export")
	})
}
