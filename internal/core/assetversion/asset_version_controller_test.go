package assetversion_test

import (
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
)

func TestBuildSBOM(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()
	app := echo.New()
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	assetVersionController := inithelper.CreateAssetVersionController(db, nil, nil, integration_tests.TestGitlabClientFactory{GitlabClientFacade: nil}, nil)
	org, project, asset := integration_tests.CreateOrgProjectAndAsset(db)
	setupContext := func(ctx core.Context) {
		authSession := mocks.NewAuthSession(t)
		core.SetAsset(ctx, asset)
		core.SetProject(ctx, project)
		core.SetOrg(ctx, org)
		core.SetSession(ctx, authSession)
	}
	buildDatabase(db, org.ID)

	t.Run("default test", func(t *testing.T) {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/sbom-json/", nil)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Scanner", "scanner-1")
		ctx := app.NewContext(req, recorder)
		setupContext(ctx)
		core.SetAssetVersion(ctx, models.AssetVersion{})
		err := assetVersionController.SBOMJSON(ctx)
		if err != nil {
			t.Fail()
		}
		var sbom []byte
		fmt.Printf("\n------------Result------------\n%s\n-------------End--------------\n", sbom)

	})
}

func buildDatabase(db core.DB, orgID uuid.UUID) {
	lo := models.LicenseOverwrite{
		LicenseID:      "Apache-2.0",
		OrganizationId: orgID,
		ComponentPurl:  "pkg:golang/filippo.io/edwards25519@v1.1.0",
		Justification:  "while the specifications place no limits on the magnitude or precision of JSON number literals, the widely used JavaScript implementation stores them as IEEE754 binary64 quantities. For interoperability, applications should avoid transmitting numbers that cannot be represented in this way, for example, 1E400 or 3.141592653589793238462643383279.",
	}
	err := db.Create(&lo).Error
	if err != nil {
		panic(err)
	}
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
