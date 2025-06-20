package asset_test

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/asset"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/inithelper"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestHandleLookup(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	assetRepo := repositories.NewAssetRepository(db)
	assetVersionRepo := repositories.NewAssetVersionRepository(db)
	assetService := mocks.NewAssetService(t)
	depVulnService := mocks.NewDependencyVulnService(t)
	statsService := mocks.NewStatisticsService(t)
	assert.Nil(t, db.AutoMigrate(
		&models.Org{},
		&models.Project{}))

	controller := asset.NewHTTPController(assetRepo, assetVersionRepo, assetService, depVulnService, statsService)

	// create an organization, project, and asset1 for testing
	_, _, asset1, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	app := echo.New()

	t.Run("should return 404 if there is no matching entity", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/lookup", nil)
		query := req.URL.Query()
		query.Add("provider", "gitlab")
		query.Add("id", "123")
		req.URL.RawQuery = query.Encode()
		ctx := app.NewContext(req, rec)

		// Use a core.Context if needed by your codebase
		err := controller.HandleLookup(ctx)
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 404, httpErr.Code)
	})

	t.Run("should find the asset and return the correct values", func(t *testing.T) {
		// update the asset to have a external entity provider and external entity id
		asset1.ExternalEntityProviderID = utils.Ptr("gitlab")
		asset1.ExternalEntityID = utils.Ptr("123")

		// save the updated asset
		assert.Nil(t, assetRepo.Save(nil, &asset1))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/lookup", nil)
		query := req.URL.Query()
		query.Add("provider", "gitlab")
		query.Add("id", "123")
		req.URL.RawQuery = query.Encode()
		ctx := app.NewContext(req, rec)
		err := controller.HandleLookup(ctx)
		assert.Nil(t, err)

		var response asset.LookupResponse
		json.Unmarshal(rec.Body.Bytes(), &response) // nolint:errcheck
		// expect the values to be correct
		assert.Equal(t, "test-org", response.Org)
		assert.Equal(t, "test-project", response.Project)
		assert.Equal(t, "test-asset", response.Asset)
		assert.Equal(t, "/api/v1/organizations/test-org/projects/test-project/assets/test-asset", response.Link)
	})
}

func TestAssetUpdate(t *testing.T) {
	os.Setenv("FRONTEND_URL", "FRONTEND_URL")
	t.Run("should be possible to enable the ticket range", func(t *testing.T) {
		db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
		defer terminate()
		assetRepo := repositories.NewAssetRepository(db)
		assetService := mocks.NewAssetService(t)
		assetVersionRepo := repositories.NewAssetVersionRepository(db)
		vulnService := inithelper.CreateDependencyVulnService(db, nil, nil, nil)

		controller := asset.NewHTTPController(assetRepo, assetVersionRepo, assetService, vulnService, nil)

		assert.Nil(t, db.AutoMigrate(
			&models.Org{},
			&models.Project{},
			&models.Asset{}))

		// create an organization, project, and asset1 for testing
		org, project, asset1, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

		updateRequest := asset.PatchRequest{
			Name:                         utils.Ptr("test-asset"),
			Description:                  utils.Ptr("test description"),
			EnableTicketRange:            true,
			CVSSAutomaticTicketThreshold: utils.Ptr(7.0),
			RiskAutomaticTicketThreshold: utils.Ptr(5.0),
		}

		updateRequestBytes, err := json.Marshal(updateRequest)
		assert.Nil(t, err)

		app := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("PATCH", "/api/v1/organizations/"+org.Slug+"/projects/"+project.Slug+"/assets/"+asset1.Slug, bytes.NewBuffer(updateRequestBytes))
		ctx := app.NewContext(req, rec)
		core.SetOrg(ctx, org)
		core.SetProject(ctx, project)
		core.SetAsset(ctx, asset1)

		err = controller.Update(ctx)
		assert.Nil(t, err)

		updatedAsset, err := assetRepo.Read(asset1.ID)
		assert.Nil(t, err)

		assert.Equal(t, 7.0, *updatedAsset.CVSSAutomaticTicketThreshold)
		assert.Equal(t, 5.0, *updatedAsset.RiskAutomaticTicketThreshold)
	})
}
