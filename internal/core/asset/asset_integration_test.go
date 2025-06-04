package asset

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
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

	controller := NewHttpController(assetRepo, assetVersionRepo, assetService, depVulnService, statsService)

	// create an organization, project, and asset for testing
	_, _, asset := integration_tests.CreateOrgProjectAndAsset(db)

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
		asset.ExternalEntityProviderID = utils.Ptr("gitlab")
		asset.ExternalEntityID = utils.Ptr("123")

		// save the updated asset
		assert.Nil(t, assetRepo.Save(nil, &asset))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/lookup", nil)
		query := req.URL.Query()
		query.Add("provider", "gitlab")
		query.Add("id", "123")
		req.URL.RawQuery = query.Encode()
		ctx := app.NewContext(req, rec)
		err := controller.HandleLookup(ctx)
		assert.Nil(t, err)

		var response LookupResponse
		json.Unmarshal(rec.Body.Bytes(), &response) // nolint:errcheck
		// expect the values to be correct
		assert.Equal(t, "test-org", response.Org)
		assert.Equal(t, "test-project", response.Project)
		assert.Equal(t, "test-asset", response.Asset)
		assert.Equal(t, "/api/v1/organizations/test-org/projects/test-project/assets/test-asset", response.Link)
	})
}
