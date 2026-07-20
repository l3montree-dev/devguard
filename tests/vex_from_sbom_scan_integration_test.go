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
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// vexDocumentForOPA builds a minimal CycloneDX VEX document (not an SBOM: it carries
// vulnerabilities, no top-level components describing a full dependency tree) that marks
// CVE-2025-46569 as not_affected for the pkg:golang/github.com/open-policy-agent/opa component.
func vexDocumentForOPA() []byte {
	return []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.6",
		"version": 1,
		"metadata": {
			"component": {
				"bom-ref": "root-app",
				"type": "application",
				"name": "root-app",
				"purl": "pkg:golang/test/app@1.0.0"
			}
		},
		"components": [
			{
				"bom-ref": "comp-opa",
				"type": "library",
				"name": "opa",
				"purl": "pkg:golang/github.com/open-policy-agent/opa@1.0.0"
			}
		],
		"vulnerabilities": [
			{
				"id": "CVE-2025-46569",
				"affects": [
					{ "ref": "comp-opa" }
				],
				"analysis": {
					"state": "not_affected",
					"detail": "not reachable in our usage"
				}
			}
		]
	}`)
}

// TestSBOMScanIngestsVEXFromExternalReferences verifies that a regular SBOM upload/scan (not
// the dedicated /vex endpoint) also creates VEX rules when the uploaded SBOM's top-level
// externalReferences point to an upstream exploitability-statement (VEX) document.
func TestSBOMScanIngestsVEXFromExternalReferences(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		createCVE2025_46569(f.DB)
		org, project, asset, _ := f.CreateOrgProjectAssetAndVersion()

		vexServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(vexDocumentForOPA())
		}))
		defer vexServer.Close()

		// decode the known-vulnerable SBOM and attach an external reference pointing at the VEX server
		var bom cdx.BOM
		decoder := cdx.NewBOMDecoder(sbomWithVulnerability(), cdx.BOMFileFormatJSON)
		require.NoError(t, decoder.Decode(&bom))
		bom.ExternalReferences = &[]cdx.ExternalReference{
			{Type: cdx.ERTypeExploitabilityStatement, URL: vexServer.URL},
		}

		var sbomBuf bytes.Buffer
		encoder := cdx.NewBOMEncoder(&sbomBuf, cdx.BOMFileFormatJSON)
		require.NoError(t, encoder.Encode(&bom))

		controller := f.App.ScanController
		app := echo.New()

		req := httptest.NewRequest("POST", "/vulndb/scan/normalized-sboms", &sbomBuf)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Artifact-Name", "artifact-vex-external-ref")
		req.Header.Set("X-Asset-Default-Branch", "main")
		req.Header.Set("X-Asset-Ref", "main")
		recorder := httptest.NewRecorder()
		ctx := app.NewContext(req, recorder)

		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("abc")
		shared.SetAsset(ctx, asset)
		shared.SetProject(ctx, project)
		shared.SetOrg(ctx, org)
		shared.SetSession(ctx, authSession)

		err := controller.ScanDependencyVulnFromProject(ctx)
		require.NoError(t, err)
		assert.Equal(t, 200, recorder.Code)

		var vexRules []models.VEXRule
		result := f.DB.Where("asset_id = ? AND cve_id = ?", asset.ID, "CVE-2025-46569").Find(&vexRules)
		require.NoError(t, result.Error)
		assert.NotEmpty(t, vexRules, "expected a VEX rule to be created from the SBOM's exploitability-statement external reference")
	})
}
