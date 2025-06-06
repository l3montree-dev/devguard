package project_test

import (
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/l3montree-dev/devguard/integration_tests"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/project"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/internal/database/repositories"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
)

func TestProjectControllerRead(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	projectRepo := repositories.NewProjectRepository(db)
	assetRepo := repositories.NewAssetRepository(db)
	projectService := project.NewService(projectRepo, assetRepo)
	controller := project.NewHttpController(projectRepo, assetRepo, projectService)

	org, project, asset, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	t.Run("should read external assets if the project is an external entity", func(t *testing.T) {
		// make the project an external entity
		project.ExternalEntityID = utils.Ptr("123")
		project.ExternalEntityProviderID = utils.Ptr("gitlab")
		db.Save(&project)
		// make the asset an external entity
		asset.ExternalEntityID = utils.Ptr("123")
		asset.ExternalEntityProviderID = utils.Ptr("gitlab")
		db.Save(&asset)

		e := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/projects/assets/", nil)
		ctx := e.NewContext(req, rec)
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("")
		core.SetSession(ctx, session)
		rbac := mocks.NewAccessControl(t)
		rbac.On("GetAllMembersOfProject", project.ID.String()).Return(nil, nil)
		core.SetRBAC(ctx, rbac)
		adminClient := mocks.NewAdminClient(t)
		adminClient.On("ListUser", mock.Anything, mock.Anything).Return(nil, nil)
		core.SetAuthAdminClient(ctx, adminClient)

		// mock the whole third party integration - we are not interested in the correct request to gitlab or any other provider
		thirdPartyIntegrationMock := mocks.NewIntegrationAggregate(t)

		thirdPartyIntegrationMock.On("ListProjects", ctx, mock.Anything, "gitlab", "123").Return([]models.Asset{asset}, nil)

		core.SetThirdPartyIntegration(ctx, thirdPartyIntegrationMock)
		core.SetOrg(ctx, org)
		core.SetProject(ctx, project)

		err := controller.Read(ctx)
		assert.Nil(t, err)
	})

	t.Run("does not overwrite asset values", func(t *testing.T) {
		project.ExternalEntityID = utils.Ptr("123")
		project.ExternalEntityProviderID = utils.Ptr("gitlab")
		db.Save(&project)
		// make the asset an external entity
		asset.ExternalEntityID = utils.Ptr("123")
		asset.ExternalEntityProviderID = utils.Ptr("gitlab")
		db.Save(&asset)

		// add a cvss automatic ticket threshold to the asset
		asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)

		e := echo.New()
		req := httptest.NewRequest("GET", "/projects/assets/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("")

		core.SetSession(ctx, session)
		rbac := mocks.NewAccessControl(t)
		rbac.On("GetAllMembersOfProject", project.ID.String()).Return(nil, nil)
		core.SetRBAC(ctx, rbac)
		adminClient := mocks.NewAdminClient(t)
		adminClient.On("ListUser", mock.Anything, mock.Anything).Return(nil, nil)
		core.SetAuthAdminClient(ctx, adminClient)

		thirdPartyIntegrationMock := mocks.NewIntegrationAggregate(t)

		thirdPartyIntegrationMock.On("ListProjects", ctx, mock.Anything, "gitlab", "123").Return([]models.Asset{asset}, nil)

		core.SetThirdPartyIntegration(ctx, thirdPartyIntegrationMock)
		core.SetOrg(ctx, org)
		core.SetProject(ctx, project)

		// You may need to mock FetchMembersOfProject or set up RBAC if required by your controller
		asset.CVSSAutomaticTicketThreshold = utils.Ptr(7.0)
		// update the asset - we expect the controller to not overwrite this value
		db.Save(&asset)

		err := controller.Read(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, rec.Code)

		// fetch the asset again to check if the CVSSAutomaticTicketThreshold is still set
		var updatedAsset models.Asset
		err = db.First(&updatedAsset, "id = ?", asset.ID).Error
		assert.Nil(t, err)
		assert.Equal(t, 7.0, *updatedAsset.CVSSAutomaticTicketThreshold)
	})
}
