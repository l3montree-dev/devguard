package assetversion_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestBuildSBOM(t *testing.T) {
	//Build up a foundation for all the upcoming tests
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()
	app := echo.New()
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	assetVersionController := inithelper.CreateAssetVersionController(db, nil, nil, integration_tests.TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	org, project, asset, assetVersion := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)
	setupContext := func(ctx *core.Context) {
		core.SetAsset(*ctx, asset)
		core.SetProject(*ctx, project)
		core.SetOrg(*ctx, org)
		core.SetAssetVersion(*ctx, assetVersion)
	}
	t.Run("test with empty db", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		fmt.Printf("\n%s\n", string(body))
		//Test the bom
		assert.Empty(t, BOMResult.Components)
		assert.Empty(t, BOMResult.Dependencies)
		assert.Equal(t, "Test Org", BOMResult.Metadata.Component.Author)
		assert.Equal(t, "github.com/l3montree-dev/devguard", BOMResult.Metadata.Component.Publisher)
		assert.Equal(t, "main", BOMResult.Metadata.Component.BOMRef)
		assert.Equal(t, "latest", BOMResult.Metadata.Component.Version)
	})
	t.Run("test with only components in the db with no specific version", func(t *testing.T) {
		createComponents(db, org.ID, asset.ID, assetVersion.Name)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		fmt.Printf("\n%s\n", string(body))
		//Test the bom
		assert.Empty(t, BOMResult.Components)
		assert.Empty(t, BOMResult.Dependencies)
		assert.Equal(t, "Test Org", BOMResult.Metadata.Component.Author)
		assert.Equal(t, "github.com/l3montree-dev/devguard", BOMResult.Metadata.Component.Publisher)
		assert.Equal(t, "main", BOMResult.Metadata.Component.BOMRef)
		assert.Equal(t, "latest", BOMResult.Metadata.Component.Version)
	})
	t.Run("test with only components in the db with an invalid version set", func(t *testing.T) {
		createComponents(db, org.ID, asset.ID, assetVersion.Name)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		params := ctx.QueryParams()
		params.Add("version", "special version")

		err := assetVersionController.SBOMJSON(ctx)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("test with only components in the db with a valid version set", func(t *testing.T) {
		createComponents(db, org.ID, asset.ID, assetVersion.Name)
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		params := ctx.QueryParams()
		params.Add("version", "2.1.9")

		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var BOMResult cyclonedx.BOM
		if err = json.Unmarshal(body, &BOMResult); err != nil {
			t.Fail()
		}

		fmt.Printf("\n%s\n", string(body))
		//Test the bom
		assert.Empty(t, BOMResult.Components)
		assert.Empty(t, BOMResult.Dependencies)
		assert.Equal(t, "Test Org", BOMResult.Metadata.Component.Author)
		assert.Equal(t, "github.com/l3montree-dev/devguard", BOMResult.Metadata.Component.Publisher)
		assert.Equal(t, "main", BOMResult.Metadata.Component.BOMRef)
		assert.Equal(t, "2.1.9", BOMResult.Metadata.Component.Version)
	})
	/*t.Run("create a normal sbom with components and dependencies and a license overwrite ", func(t *testing.T) {
		//Setup environment for this test
		buildDatabase(db, org.ID, asset.ID, "main", "with license overwrite, components and dependencies")
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(&ctx)
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}

		//Process the results into an BOM
		resp := recorder.Result()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fail()
		}
		var jsonBOM cyclonedx.BOM
		if err = json.Unmarshal(body, &jsonBOM); err != nil {
			t.Fail()
		}

		//Test the BOM

	})*/
}
func createComponents(db core.DB, orgID uuid.UUID, assetID uuid.UUID, assetVersionName string) {
	componentProject := models.ComponentProject{
		ProjectKey:      "github.com/xyflow/xyflow",
		StarsCount:      2993,
		ForksCount:      282,
		OpenIssuesCount: 0,
		License:         "MIT",
		ScoreCardScore:  utils.Ptr(5.2),
	}
	err := db.Create(&componentProject).Error
	if err != nil {
		panic(err)
	}
	component1 := models.Component{
		Purl:             "pkg:npm/@xyflow/system@0.0.42",
		ComponentType:    models.ComponentTypeLibrary,
		Version:          "0.0.42",
		License:          utils.Ptr("MIT"),
		Published:        utils.Ptr(time.Now()),
		ComponentProject: &componentProject,
	}
	err = db.Create(&component1).Error
	if err != nil {
		panic(err)
	}
	component2 := models.Component{
		Purl:             "pkg:npm/@xyflow/react@12.3.0",
		ComponentType:    models.ComponentTypeLibrary,
		Version:          "12.3.0",
		License:          utils.Ptr("MIT"),
		Published:        utils.Ptr(time.Now()),
		ComponentProject: &componentProject,
	}
	err = db.Create(&component2).Error
	if err != nil {
		panic(err)
	}
}

func buildDatabase(db core.DB, orgID uuid.UUID, assetID uuid.UUID, assetVersionName string, mode string) {

	var err error
	if strings.Contains(mode, "license overwrite") {
		lo := models.LicenseOverwrite{
			LicenseID:      "Apache-2.0",
			OrganizationId: orgID,
			ComponentPurl:  "pkg:npm/@xyflow/system@0.0.42",
			Justification:  "while the specifications place no limits on the magnitude or precision of JSON number literals, the widely used JavaScript implementation stores them as IEEE754 binary64 quantities. For interoperability, applications should avoid transmitting numbers that cannot be represented in this way, for example, 1E400 or 3.141592653589793238462643383279.",
		}
		err = db.Create(&lo).Error
		if err != nil {
			panic(err)
		}
	}
	if strings.Contains(mode, "components") {
		componentProject := models.ComponentProject{
			ProjectKey:      "github.com/xyflow/xyflow",
			StarsCount:      2993,
			ForksCount:      282,
			OpenIssuesCount: 0,
			License:         "MIT",
			ScoreCardScore:  utils.Ptr(5.2),
		}
		err = db.Create(&componentProject).Error
		if err != nil {
			panic(err)
		}
		component1 := models.Component{
			Purl:             "pkg:npm/@xyflow/system@0.0.42",
			ComponentType:    models.ComponentTypeLibrary,
			Version:          "0.0.42",
			License:          utils.Ptr("MIT"),
			Published:        utils.Ptr(time.Now()),
			ComponentProject: &componentProject,
		}
		err = db.Create(&component1).Error
		if err != nil {
			panic(err)
		}
		component2 := models.Component{
			Purl:             "pkg:npm/@xyflow/react@12.3.0",
			ComponentType:    models.ComponentTypeLibrary,
			Version:          "12.3.0",
			License:          utils.Ptr("MIT"),
			Published:        utils.Ptr(time.Now()),
			ComponentProject: &componentProject,
		}
		err = db.Create(&component2).Error
		if err != nil {
			panic(err)
		}
	}

	if strings.Contains(mode, "dependencies") {
		component_dependency0 := models.ComponentDependency{
			ComponentPurl:    nil,
			DependencyPurl:   "pkg:npm/@xyflow/system@0.0.42",
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			Depth:            0,
			ScannerIDs:       "SBOM-File-Upload",
		}
		err = db.Create(&component_dependency0).Error
		if err != nil {
			panic(err)
		}

		component_dependency1 := models.ComponentDependency{
			ComponentPurl:    utils.Ptr("pkg:npm/@xyflow/system@0.0.42"),
			DependencyPurl:   "pkg:npm/@xyflow/react@12.3.0",
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			Depth:            0,
			ScannerIDs:       "SBOM-File-Upload",
		}
		err = db.Create(&component_dependency1).Error
		if err != nil {
			panic(err)
		}
		component_dependency2 := models.ComponentDependency{
			ComponentPurl:    utils.Ptr("pkg:npm/@xyflow/react@12.3.0"),
			DependencyPurl:   "pkg:npm/@xyflow/system@0.0.42",
			AssetID:          assetID,
			AssetVersionName: assetVersionName,
			Depth:            0,
			ScannerIDs:       "SBOM-File-Upload",
		}
		err = db.Create(&component_dependency2).Error
		if err != nil {
			panic(err)
		}
	}
}
