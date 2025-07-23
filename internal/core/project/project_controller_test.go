package project_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/gosimple/slug"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	integration_tests "github.com/l3montree-dev/devguard/integrationtestutil"
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
	controller := project.NewHTTPController(projectRepo, assetRepo, projectService)

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

func TestProjectControllerList(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	projectRepo := repositories.NewProjectRepository(db)
	assetRepo := repositories.NewAssetRepository(db)
	projectService := project.NewService(projectRepo, assetRepo)
	controller := project.NewHTTPController(projectRepo, assetRepo, projectService)
	org, project, _, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	// add 3 community policies to the database
	communityPolicies := []models.Policy{
		{
			Title:          "Community Policy 1",
			Description:    "This is a community policy",
			OrganizationID: nil, // nil means it's a community policy
			OpaqueID:       "community-policy-1",
		},
		{
			Title:          "Community Policy 2",
			Description:    "This is another community policy",
			OrganizationID: nil, // nil means it's a community policy
			OpaqueID:       "community-policy-2",
		},
		{
			Title:          "Community Policy 3",
			Description:    "This is yet another community policy",
			OrganizationID: nil, // nil means it's a community policy
			OpaqueID:       "community-policy-3",
		},
	}
	assert.Nil(t, db.Create(&communityPolicies).Error)

	t.Run("should enable all community policies by default (only for new projects)", func(t *testing.T) {
		// make the project an external entity
		project.ExternalEntityID = utils.Ptr("123")
		project.ExternalEntityProviderID = utils.Ptr("gitlab")
		db.Save(&project)

		e := echo.New()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/projects/assets/", nil)
		ctx := e.NewContext(req, rec)
		rbacMock := mocks.NewAccessControl(t)
		newProject := models.Project{
			Slug:                     "new-project",
			Name:                     "New Project",
			Description:              "This is a new project",
			OrganizationID:           org.ID,
			ExternalEntityID:         utils.Ptr("456"),
			ExternalEntityProviderID: utils.Ptr("gitlab"),
		}

		rbacMock.On("GetAllProjectsForUser", mock.Anything).Return([]models.Project{project, newProject}, nil)
		rbacMock.On("GetExternalEntityProviderID").Return(utils.Ptr("gitlab"))
		session := mocks.NewAuthSession(t)
		session.On("GetUserID").Return("")
		core.SetRBAC(ctx, rbacMock)
		core.SetSession(ctx, session)
		core.SetOrg(ctx, org)
		adminClient := mocks.NewAdminClient(t)
		core.SetAuthAdminClient(ctx, adminClient)

		err := controller.List(ctx)
		assert.Nil(t, err)
		// expect the existing project to not have any community policies enabled
		db.Preload("EnabledPolicies").First(&project, "id = ?", project.ID)
		assert.Empty(t, project.EnabledPolicies, "Existing project should not get all community policies enabled")
		// expect the new project to have all community policies enabled
		db.Preload("EnabledPolicies").First(&newProject, "slug = ?", newProject.Slug)
		assert.NotEmpty(t, newProject.EnabledPolicies, "New project should have all community policies enabled")
		assert.Len(t, newProject.EnabledPolicies, 3, "New project should have exactly 3 community policies enabled")

	})
}

func TestProjectCreation(t *testing.T) {
	db, terminate := integration_tests.InitDatabaseContainer("../../../initdb.sql")
	defer terminate()

	controller := project.NewHTTPController(
		repositories.NewProjectRepository(db),
		repositories.NewAssetRepository(db),
		project.NewService(
			repositories.NewProjectRepository(db),
			repositories.NewAssetRepository(db),
		),
	)

	org, project, _, _ := integration_tests.CreateOrgProjectAndAssetAssetVersion(db)

	t.Run("should enable all community policies by default", func(t *testing.T) {
		e := echo.New()
		rec := httptest.NewRecorder()
		// create a community policy
		communityPolicy := models.Policy{
			Title:          "Community Policy 1",
			Description:    "This is a community policy",
			OrganizationID: nil, // nil means it's a community policy
		}

		assert.Nil(t, db.Create(&communityPolicy).Error)

		requestBody := map[string]string{
			"name":        "new-project",
			"description": "This is a new project",
		}

		b, err := json.Marshal(requestBody)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "/projects", bytes.NewBuffer(b))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx := e.NewContext(req, rec)
		core.SetOrg(ctx, org)
		session := mocks.NewAuthSession(t)
		core.SetSession(ctx, session)
		rbac := mocks.NewAccessControl(t)
		rbac.On("LinkDomainAndProjectRole", "admin", "admin", mock.Anything).Return(nil)
		rbac.On("InheritProjectRole", "admin", "member", mock.Anything).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "admin", core.ObjectUser, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "admin", core.ObjectAsset, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "admin", core.ObjectProject, []core.Action{
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "member", core.ObjectProject, []core.Action{
			core.ActionRead,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "member", core.ObjectAsset, []core.Action{
			core.ActionRead,
		}).Return(nil)

		core.SetRBAC(ctx, rbac)

		err = controller.Create(ctx)
		assert.Nil(t, err)

		var createdProject models.Project
		err = db.Preload("EnabledPolicies").First(&createdProject, "slug = ?", requestBody["name"]).Error

		assert.Nil(t, err)
		assert.Len(t, createdProject.EnabledPolicies, 1)
	})

	t.Run("should generate a unique slug", func(t *testing.T) {
		// create a new project with the same name and slug as the existing project
		e := echo.New()
		rec := httptest.NewRecorder()
		requestBody := map[string]string{
			"name":        project.Name,
			"description": "This is a new project with the same name",
		}

		b, err := json.Marshal(requestBody)
		assert.Nil(t, err)

		req := httptest.NewRequest("POST", "/projects", bytes.NewBuffer(b))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx := e.NewContext(req, rec)
		core.SetOrg(ctx, org)
		session := mocks.NewAuthSession(t)
		core.SetSession(ctx, session)
		rbac := mocks.NewAccessControl(t)
		rbac.On("LinkDomainAndProjectRole", "admin", "admin", mock.Anything).Return(nil)

		rbac.On("InheritProjectRole", "admin", "member", mock.Anything).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "admin", core.ObjectUser, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)

		rbac.On("AllowRoleInProject", mock.Anything, "admin", core.ObjectAsset, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "admin", core.ObjectProject, []core.Action{
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "member", core.ObjectProject, []core.Action{
			core.ActionRead,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, "member", core.ObjectAsset, []core.Action{
			core.ActionRead,
		}).Return(nil)
		core.SetRBAC(ctx, rbac)

		err = controller.Create(ctx)
		assert.Nil(t, err)
		assert.Equal(t, 200, rec.Code)
		var response models.Project
		err = json.Unmarshal(rec.Body.Bytes(), &response)
		assert.Nil(t, err)

		// check that the slug is unique
		assert.Equal(t, fmt.Sprintf("%s-2", slug.Make(project.Name)), response.Slug, "The slug should be unique")
	})
}
