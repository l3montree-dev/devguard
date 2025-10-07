// Copyright (C) 2025 l3montree GmbH
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

package release_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
	"github.com/l3montree-dev/devguard/internal/core"
	releasepkg "github.com/l3montree-dev/devguard/internal/core/release"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

// TestReleaseVEXMergeIntegration verifies that the release VEX endpoint returns a merged VeX (CycloneDX BOM with vulnerabilities)
func TestReleaseVEXMergeIntegration(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "http://localhost:3000")
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	// repositories
	avRepo := repositories.NewAssetVersionRepository(db)
	compRepo := repositories.NewComponentRepository(db)
	releaseRepo := repositories.NewReleaseRepository(db)
	licenseRiskRepo := repositories.NewLicenseRiskRepository(db)
	dependencyVulnRepo := repositories.NewDependencyVulnRepository(db)
	assetRepository := repositories.NewAssetRepository(db)

	// services using inithelper to follow repository patterns
	avService := inithelper.CreateAssetVersionService(db, nil, nil, integration_tests.TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	relService := releasepkg.NewService(releaseRepo)

	// create an artifact
	a := models.Artifact{ArtifactName: "artifact-x", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
	if err := db.Create(&a).Error; err != nil {
		t.Fatal(err)
	}

	// create a CVE that the dependency vuln will reference
	cve := models.CVE{CVE: "CVE-2025-0001", Description: "test vuln", CVSS: 7.5, Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}
	if err := db.Create(&cve).Error; err != nil {
		t.Fatal(err)
	}

	// create a dependency vuln referencing the CVE and the artifact
	dv := models.DependencyVuln{
		Vulnerability:  models.Vulnerability{AssetVersionName: assetVersion.Name, AssetID: asset.ID},
		CVEID:          &cve.CVE,
		ComponentPurl:  utils.Ptr("pkg:maven/org.example/component-x@1.2.3"),
		Artifacts:      []models.Artifact{a},
		ComponentDepth: utils.Ptr(1),
	}
	if err := db.Create(&dv).Error; err != nil {
		t.Fatal(err)
	}

	// create release with item referencing the artifact
	rel := models.Release{Name: "vex-release", ProjectID: project.ID}
	if err := db.Create(&rel).Error; err != nil {
		t.Fatal(err)
	}
	item := models.ReleaseItem{ReleaseID: rel.ID, ArtifactName: &a.ArtifactName, AssetVersionName: &a.AssetVersionName, AssetID: &a.AssetID}
	if err := db.Create(&item).Error; err != nil {
		t.Fatal(err)
	}

	// controller
	releaseController := releasepkg.NewReleaseController(relService, avService, avRepo, compRepo, licenseRiskRepo, dependencyVulnRepo, assetRepository)

	r := echo.New()
	req := httptest.NewRequest("GET", "/projects/test-project/releases/"+rel.ID.String()+"/vex.json", nil)
	rec := httptest.NewRecorder()
	ctx := r.NewContext(req, rec)
	ctx.SetPath("/projects/:projectSlug/releases/:releaseId/vex.json")
	ctx.SetParamNames("projectSlug", "releaseID")
	ctx.SetParamValues(project.Slug, rel.ID.String())

	core.SetOrg(ctx, org)
	core.SetProject(ctx, project)

	if err := releaseController.VEXJSON(ctx); err != nil {
		t.Fatalf("VEXJSON returned error: %v", err)
	}

	var bom cdx.BOM
	if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&bom); err != nil {
		t.Fatalf("could not decode response as BOM: %v", err)
	}

	assert.NotNil(t, bom.Vulnerabilities)
	assert.GreaterOrEqual(t, len(*bom.Vulnerabilities), 1)
}
