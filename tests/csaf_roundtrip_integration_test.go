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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// createRoundTripVuln inserts one path-specific DependencyVuln (plus a detected event, and
// optionally a false-positive event) for the given CVE/component/path.
func createRoundTripVuln(t *testing.T, db shared.DB, assetID uuid.UUID, assetVersionName string, artifact models.Artifact, cve *models.CVE, comp string, path []string, state dtos.VulnState, falsePositive bool) models.DependencyVuln {
	t.Helper()
	v := models.DependencyVuln{
		Vulnerability:     models.Vulnerability{AssetVersionName: assetVersionName, AssetID: assetID, State: state},
		ComponentPurl:     comp,
		CVE:               cve,
		CVEID:             cve.CVE,
		VulnerabilityPath: path,
		RawRiskAssessment: new(4.83),
		Artifacts:         []models.Artifact{artifact},
	}
	assert.NoError(t, db.Create(&v).Error)
	assert.NoError(t, db.Model(&artifact).Association("DependencyVuln").Append(&v))

	detected := models.VulnEvent{DependencyVulnID: new(v.ID), CreatedAt: time.Now().Add(-10 * time.Minute), Type: dtos.EventTypeDetected, UserID: "system"}
	assert.NoError(t, db.Create(&detected).Error)

	if falsePositive {
		fp := models.VulnEvent{
			DependencyVulnID:        new(v.ID),
			CreatedAt:               time.Now().Add(-1 * time.Minute),
			Type:                    dtos.EventTypeFalsePositive,
			UserID:                  "system",
			Justification:           new("not reachable in our usage"),
			MechanicalJustification: dtos.VulnerableCodeNotInExecutePath,
		}
		assert.NoError(t, db.Create(&fp).Error)
	}
	return v
}

// postVEX drives the real POST /vex/ endpoint with the given document body.
func postVEX(t *testing.T, f *TestFixture, org models.Org, project models.Project, asset models.Asset, assetRef, artifactName string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/vex/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Asset-Ref", assetRef)
	req.Header.Set("X-Artifact-Name", artifactName)
	req.Header.Set("X-Origin", "csaf-roundtrip")

	recorder := httptest.NewRecorder()
	ctx := echo.New().NewContext(req, recorder)
	shared.SetAsset(ctx, asset)
	shared.SetProject(ctx, project)
	shared.SetOrg(ctx, org)

	assert.NoError(t, f.App.ScanController.UploadVEX(ctx))
	return recorder
}

// roundTripVulnStatesByPathHead maps each vuln's first path element to its state.
func roundTripVulnStatesByPathHead(t *testing.T, db shared.DB, assetID uuid.UUID, cveID string) map[string]dtos.VulnState {
	t.Helper()
	var vulns []models.DependencyVuln
	assert.NoError(t, db.Where("asset_id = ? AND cve_id = ?", assetID, cveID).Find(&vulns).Error)
	states := map[string]dtos.VulnState{}
	for _, v := range vulns {
		assert.NotEmpty(t, v.VulnerabilityPath)
		states[v.VulnerabilityPath[0]] = v.State
	}
	return states
}

// TestCSAFRoundTripPathSpecific verifies that DevGuard can ingest its own CSAF report and
// only the path-specific vulnerability is closed - not every path of the same component.
//
// Setup: one CVE in one component reached via two distinct dependency paths. Path A is a
// false positive, path B is open. We generate a CSAF report (which encodes each path as a
// relationship chain), then ingest that report into a *fresh* asset where both paths are
// still open, and assert that ingestion closes only path A.
func TestCSAFRoundTripPathSpecific(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		ctx := context.Background()
		org, project, sourceAsset, sourceVersion := f.CreateOrgProjectAssetAndVersion()

		const comp = "pkg:npm/lodash@4.17.20"
		const depA, depB = "pkg:npm/dep-a@1.0.0", "pkg:npm/dep-b@1.0.0"
		pathA := []string{depA, comp} // false positive
		pathB := []string{depB, comp} // stays open

		cve := models.CVE{CVE: "CVE-2024-9999", Description: "round trip test", CVSS: 7.5}
		assert.NoError(t, f.DB.Create(&cve).Error)

		// source asset: path A is a false positive, path B is open.
		sourceArtifact := models.Artifact{ArtifactName: "pkg:oci/source-app", AssetVersionName: sourceVersion.Name, AssetID: sourceAsset.ID}
		assert.NoError(t, f.DB.Create(&sourceArtifact).Error)
		createRoundTripVuln(t, f.DB, sourceAsset.ID, sourceVersion.Name, sourceArtifact, &cve, comp, pathA, dtos.VulnStateFalsePositive, true)
		createRoundTripVuln(t, f.DB, sourceAsset.ID, sourceVersion.Name, sourceArtifact, &cve, comp, pathB, dtos.VulnStateOpen, false)

		// target asset: the SAME two paths, but BOTH open - this is what ingestion acts on.
		targetAsset := f.CreateAsset(project.ID, "target-asset")
		targetVersion := f.CreateAssetVersion(targetAsset.ID, "main", true)
		targetArtifact := models.Artifact{ArtifactName: "pkg:oci/target-app", AssetVersionName: targetVersion.Name, AssetID: targetAsset.ID}
		assert.NoError(t, f.DB.Create(&targetArtifact).Error)
		createRoundTripVuln(t, f.DB, targetAsset.ID, targetVersion.Name, targetArtifact, &cve, comp, pathA, dtos.VulnStateOpen, false)
		createRoundTripVuln(t, f.DB, targetAsset.ID, targetVersion.Name, targetArtifact, &cve, comp, pathB, dtos.VulnStateOpen, false)

		// advisory is generated in the first subtest and re-used by the ingestion subtest
		var advisory gocsaf.Advisory

		t.Run("generates a CSAF report", func(t *testing.T) {
			var err error
			advisory, err = f.App.CSAFService.GenerateCSAFReport(ctx, org.Name, sourceAsset.ID, sourceAsset.Name, cve.CVE)
			assert.NoError(t, err)
			assert.NotNil(t, advisory.ProductTree)
		})

		t.Run("POST /vex/ with the CSAF closes only the path-specific vuln", func(t *testing.T) {
			body, err := json.Marshal(advisory)
			assert.NoError(t, err)

			recorder := postVEX(t, f, org, project, targetAsset, targetVersion.Name, targetArtifact.ArtifactName, body)
			assert.Equal(t, http.StatusOK, recorder.Code)

			// a single, non-wildcard rule was created from the false-positive path
			var vexRules []models.VEXRule
			assert.NoError(t, f.DB.Where("asset_id = ? AND cve_id = ?", targetAsset.ID, cve.CVE).Find(&vexRules).Error)
			assert.Len(t, vexRules, 1)
			assert.Equal(t, dtos.EventTypeFalsePositive, vexRules[0].EventType)
			assert.Equal(t, pathA, []string(vexRules[0].PathPattern), "must be the exact path A, not a wildcard")

			// only path A is closed; path B stays open
			states := roundTripVulnStatesByPathHead(t, f.DB, targetAsset.ID, cve.CVE)
			assert.Equal(t, dtos.VulnStateFalsePositive, states[depA], "path A must be closed as false positive")
			assert.Equal(t, dtos.VulnStateOpen, states[depB], "path B must remain open - the per-path granularity CycloneDX cannot provide")
		})
	})
}
