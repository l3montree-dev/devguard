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
	"github.com/l3montree-dev/devguard/mocks"
)

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
		repositories.NewWebhookRepository(db),
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
		rbac.On("LinkDomainAndProjectRole", core.RoleAdmin, core.RoleAdmin, mock.Anything).Return(nil)
		rbac.On("InheritProjectRole", core.RoleAdmin, core.RoleMember, mock.Anything).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleAdmin, core.ObjectUser, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleAdmin, core.ObjectAsset, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleAdmin, core.ObjectProject, []core.Action{
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleMember, core.ObjectProject, []core.Action{
			core.ActionRead,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleMember, core.ObjectAsset, []core.Action{
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
		rbac.On("LinkDomainAndProjectRole", core.RoleAdmin, core.RoleAdmin, mock.Anything).Return(nil)

		rbac.On("InheritProjectRole", core.RoleAdmin, core.RoleMember, mock.Anything).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleAdmin, core.ObjectUser, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)

		rbac.On("AllowRoleInProject", mock.Anything, core.RoleAdmin, core.ObjectAsset, []core.Action{
			core.ActionCreate,
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleAdmin, core.ObjectProject, []core.Action{
			core.ActionDelete,
			core.ActionUpdate,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleMember, core.ObjectProject, []core.Action{
			core.ActionRead,
		}).Return(nil)
		rbac.On("AllowRoleInProject", mock.Anything, core.RoleMember, core.ObjectAsset, []core.Action{
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
