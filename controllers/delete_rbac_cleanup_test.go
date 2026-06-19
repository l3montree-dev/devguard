package controllers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestOrgControllerDeleteRevokesDomainRoles(t *testing.T) {
	e := echo.New()

	t.Run("removes all domain roles after deleting the org", func(t *testing.T) {
		ctx := e.NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), httptest.NewRecorder())
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		shared.SetOrg(ctx, org)

		repo := mocks.NewOrganizationRepository(t)
		repo.On("Delete", mock.Anything, mock.Anything, org.ID).Return(nil)
		provider := mocks.NewRBACProvider(t)
		provider.On("RevokeAllRolesForDomain", org.ID).Return(nil)

		controller := &OrgController{organizationRepository: repo, rbacProvider: provider}
		assert.NoError(t, controller.Delete(ctx))
	})

	t.Run("returns 500 when role cleanup fails", func(t *testing.T) {
		ctx := e.NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), httptest.NewRecorder())
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		shared.SetOrg(ctx, org)

		repo := mocks.NewOrganizationRepository(t)
		repo.On("Delete", mock.Anything, mock.Anything, org.ID).Return(nil)
		provider := mocks.NewRBACProvider(t)
		provider.On("RevokeAllRolesForDomain", org.ID).Return(errors.New("boom"))

		controller := &OrgController{organizationRepository: repo, rbacProvider: provider}
		err := controller.Delete(ctx)

		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
	})
}

func TestProjectControllerDeleteCascadesToNestedProjectsAndAssets(t *testing.T) {
	e := echo.New()

	parent := models.Project{Model: models.Model{ID: uuid.New()}}
	child := models.Project{Model: models.Model{ID: uuid.New()}}
	parentAsset := models.Asset{Model: models.Model{ID: uuid.New()}}
	childAsset := models.Asset{Model: models.Model{ID: uuid.New()}}

	t.Run("revokes roles for the whole subtree and its assets", func(t *testing.T) {
		ctx := e.NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), httptest.NewRecorder())
		shared.SetProject(ctx, parent)

		projectRepo := mocks.NewProjectRepository(t)
		projectRepo.On("RecursivelyGetChildProjects", mock.Anything, mock.Anything, parent.ID).Return([]models.Project{child}, nil)
		projectRepo.On("Delete", mock.Anything, mock.Anything, parent.ID).Return(nil)

		assetRepo := mocks.NewAssetRepository(t)
		// both the parent and the child project id must be queried for assets
		assetRepo.On("GetByProjectIDs", mock.Anything, mock.Anything, mock.MatchedBy(func(ids []uuid.UUID) bool {
			return len(ids) == 2 && ids[0] == parent.ID && ids[1] == child.ID
		})).Return([]models.Asset{parentAsset, childAsset}, nil)

		rbac := mocks.NewAccessControl(t)
		rbac.On("RevokeAllRolesInProject", mock.Anything, parent.ID.String()).Return(nil)
		rbac.On("RevokeAllRolesInProject", mock.Anything, child.ID.String()).Return(nil)
		rbac.On("RevokeAllRolesInAsset", mock.Anything, parentAsset.ID.String()).Return(nil)
		rbac.On("RevokeAllRolesInAsset", mock.Anything, childAsset.ID.String()).Return(nil)
		shared.SetRBAC(ctx, rbac)

		controller := &ProjectController{projectRepository: projectRepo, assetRepository: assetRepo}
		assert.NoError(t, controller.Delete(ctx))
	})

	t.Run("does not touch rbac when the db delete fails", func(t *testing.T) {
		ctx := e.NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), httptest.NewRecorder())
		shared.SetProject(ctx, parent)

		projectRepo := mocks.NewProjectRepository(t)
		projectRepo.On("RecursivelyGetChildProjects", mock.Anything, mock.Anything, parent.ID).Return(nil, nil)
		projectRepo.On("Delete", mock.Anything, mock.Anything, parent.ID).Return(errors.New("db error"))

		assetRepo := mocks.NewAssetRepository(t)
		assetRepo.On("GetByProjectIDs", mock.Anything, mock.Anything, mock.Anything).Return([]models.Asset{}, nil)

		// rbac mock has no expectations - any revoke call would fail the test
		rbac := mocks.NewAccessControl(t)
		shared.SetRBAC(ctx, rbac)

		controller := &ProjectController{projectRepository: projectRepo, assetRepository: assetRepo}
		assert.Error(t, controller.Delete(ctx))
	})
}

func TestAssetControllerDeleteRevokesAssetRoles(t *testing.T) {
	e := echo.New()
	ctx := e.NewContext(httptest.NewRequest(http.MethodDelete, "/", nil), httptest.NewRecorder())

	asset := models.Asset{Model: models.Model{ID: uuid.New()}}
	shared.SetAsset(ctx, asset)

	assetRepo := mocks.NewAssetRepository(t)
	assetRepo.On("Delete", mock.Anything, mock.Anything, asset.ID).Return(nil)

	rbac := mocks.NewAccessControl(t)
	rbac.On("RevokeAllRolesInAsset", mock.Anything, asset.ID.String()).Return(nil)
	shared.SetRBAC(ctx, rbac)

	controller := &AssetController{assetRepository: assetRepo}
	assert.NoError(t, controller.Delete(ctx))
}
