package controllers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/l3montree-dev/devguard/tests"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandleLookup(t *testing.T) {
	db, terminate := tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	assetRepo := repositories.NewAssetRepository(db)
	assetVersionRepo := repositories.NewAssetVersionRepository(db)
	assetService := mocks.NewAssetService(t)
	depVulnService := mocks.NewDependencyVulnService(t)
	statsService := mocks.NewStatisticsService(t)
	thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)

	controller := NewAssetController(assetRepo, assetVersionRepo, assetService, depVulnService, statsService, thirdPartyIntegration)

	// create an organization, project, and asset1 for testing
	_, _, asset1, _ := tests.CreateOrgProjectAndAssetAssetVersion(db)

	app := echo.New()

	t.Run("should return 404 if there is no matching entity", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/lookup", nil)
		query := req.URL.Query()
		query.Add("provider", "gitlab")
		query.Add("id", "123")
		req.URL.RawQuery = query.Encode()
		ctx := app.NewContext(req, rec)

		// Use a shared.Context if needed by your codebase
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

		var response dtos.LookupResponse
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
		db, terminate := tests.InitDatabaseContainer("../../../initdb.sql")
		defer terminate()
		assetRepo := repositories.NewAssetRepository(db)
		assetService := mocks.NewAssetService(t)
		assetVersionRepo := repositories.NewAssetVersionRepository(db)
		vulnService := tests.CreateDependencyVulnService(db, nil, nil, nil)
		thirdPartyIntegration := mocks.NewThirdPartyIntegration(t)

		thirdPartyIntegration.On("CreateLabels", mock.Anything, mock.Anything).Return(nil)

		controller := NewAssetController(assetRepo, assetVersionRepo, assetService, vulnService, nil, thirdPartyIntegration)

		// create an organization, project, and asset1 for testing
		org, project, asset1, _ := tests.CreateOrgProjectAndAssetAssetVersion(db)

		updateRequest := dtos.AssetPatchRequest{
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
		rbac := mocks.NewAccessControl(t)
		rbac.On("GetAllMembersOfAsset", asset1.ID.String()).Return(nil, nil)

		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset1)
		shared.SetRBAC(ctx, rbac)

		err = controller.Update(ctx)
		assert.Nil(t, err)

		updatedAsset, err := assetRepo.Read(asset1.ID)
		assert.Nil(t, err)

		assert.Equal(t, 7.0, *updatedAsset.CVSSAutomaticTicketThreshold)
		assert.Equal(t, 5.0, *updatedAsset.RiskAutomaticTicketThreshold)
	})
}
