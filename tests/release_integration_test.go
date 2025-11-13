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

package tests

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/l3montree-dev/devguard/controllers"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/services"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestReleaseSBOMMergeIntegration(t *testing.T) {
	db, terminate := InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	os.Setenv("FRONTEND_URL", "http://localhost:3000")
	org, project, asset, assetVersion := CreateOrgProjectAndAssetAssetVersion(db)

	// repositories
	avRepo := repositories.NewAssetVersionRepository(db)
	compRepo := repositories.NewComponentRepository(db)
	releaseRepo := repositories.NewReleaseRepository(db)
	licenseRiskRepo := repositories.NewLicenseRiskRepository(db)
	dependencyVulnRepo := repositories.NewDependencyVulnRepository(db)
	assetRepository := repositories.NewAssetRepository(db)
	// services using inithelper to follow repository patterns
	avService := CreateAssetVersionService(db, nil, nil, TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	relService := services.NewReleaseService(releaseRepo)

	// use subtests: setup and then call SBOM endpoint
	var (
		a1  models.Artifact
		a2  models.Artifact
		rel models.Release
		r   = echo.New()
	)

	// create two artifacts
	a1 = models.Artifact{ArtifactName: "artifact-a", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
	if err := db.Create(&a1).Error; err != nil {
		t.Fatal(err)
	}
	a2 = models.Artifact{ArtifactName: "artifact-b", AssetVersionName: assetVersion.Name, AssetID: asset.ID}
	if err := db.Create(&a2).Error; err != nil {
		t.Fatal(err)
	}

	// ensure Component rows exist for the dependency purls (FK to components.purl)
	compA := models.Component{Purl: "pkg:maven/org.example/component-a@1.0.0", Version: "1.0.0"}
	compB := models.Component{Purl: "pkg:maven/org.example/component-b@2.0.0", Version: "2.0.0"}
	if err := db.Create(&compA).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&compB).Error; err != nil {
		t.Fatal(err)
	}

	c1 := models.ComponentDependency{DependencyPurl: compA.Purl, AssetVersionName: assetVersion.Name, AssetID: asset.ID, Artifacts: []models.Artifact{a1}}
	c2 := models.ComponentDependency{DependencyPurl: compB.Purl, AssetVersionName: assetVersion.Name, AssetID: asset.ID, Artifacts: []models.Artifact{a2}}
	if err := db.Create(&c1).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&c2).Error; err != nil {
		t.Fatal(err)
	}

	// create release with items referencing artifacts
	rel = models.Release{Name: "test-release", ProjectID: project.ID}
	if err := db.Create(&rel).Error; err != nil {
		t.Fatal(err)
	}
	item1 := models.ReleaseItem{ReleaseID: rel.ID, ArtifactName: &a1.ArtifactName, AssetVersionName: &a1.AssetVersionName, AssetID: &a1.AssetID}
	item2 := models.ReleaseItem{ReleaseID: rel.ID, ArtifactName: &a2.ArtifactName, AssetVersionName: &a2.AssetVersionName, AssetID: &a2.AssetID}
	if err := db.Create(&item1).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Create(&item2).Error; err != nil {
		t.Fatal(err)
	}

	t.Run("sbom returns merged components", func(t *testing.T) {
		// build controller using repo/service patterns
		releaseController := controllers.NewReleaseController(relService, avService, avRepo, compRepo, licenseRiskRepo, dependencyVulnRepo, assetRepository)

		// prepare context with echo request/recorder
		req := httptest.NewRequest("GET", "/projects/test-project/releases/"+rel.ID.String()+"/sbom.json", nil)
		rec := httptest.NewRecorder()
		ctx := r.NewContext(req, rec)

		// inject route params expected by controller
		ctx.SetPath("/projects/:projectSlug/releases/:releaseID/sbom.json")
		ctx.SetParamNames("projectSlug", "releaseID")
		ctx.SetParamValues(project.Slug, rel.ID.String())

		// attach required objects into echo.Context using shared.Set helpers (shared.Context is alias to echo.Context)
		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)

		// call SBOMJSON directly with ctx (shared.Context is an alias of echo.Context)
		if err := releaseController.SBOMJSON(ctx); err != nil {
			t.Fatalf("SBOMJSON returned error: %v", err)
		}

		// parse response as CycloneDX BOM
		var bom cdx.BOM
		if err := json.NewDecoder(bytes.NewReader(rec.Body.Bytes())).Decode(&bom); err != nil {
			t.Fatalf("could not decode response as BOM: %v", err)
		}

		// expect two components
		assert.NotNil(t, bom.Components)
		assert.GreaterOrEqual(t, len(*bom.Components), 2)
	})
}
