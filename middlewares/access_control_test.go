// Copyright (C) 2025 l3montree Gmb	t.Run("allows access with correct organization permissions", func(t *testing.T) {
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

package middlewares

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestInstanceAdminMiddleware tests the instance admin middleware
func TestInstanceAdminMiddleware(t *testing.T) {
	t.Run("allows access when PAT verifies as admin", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.NewPersonalAccessTokenService(t)
		mockPAT.EXPECT().VerifyAdminRequest(req).Return(true, nil)

		middleware := InstanceAdminMiddleware(mockPAT)

		// Act: capture the session the middleware sets so we can assert it is elevated
		var gotSession shared.AuthSession
		err := middleware(func(ctx echo.Context) error {
			gotSession = shared.GetSession(ctx)
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		// the whole point of the middleware: elevate to an admin session
		assert.NotNil(t, gotSession)
		assert.True(t, gotSession.IsInstanceAdmin())
		assert.Equal(t, "admin", gotSession.GetActorID())
	})

	t.Run("denies access when PAT is valid but not an admin", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.NewPersonalAccessTokenService(t)
		mockPAT.EXPECT().VerifyAdminRequest(req).Return(false, nil)

		middleware := InstanceAdminMiddleware(mockPAT)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	})

	t.Run("denies access when PAT verification fails", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.NewPersonalAccessTokenService(t)
		mockPAT.EXPECT().VerifyAdminRequest(req).Return(false, errors.New("invalid signature"))

		middleware := InstanceAdminMiddleware(mockPAT)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusUnauthorized, httpErr.Code)
	})
}

// TestOrganizationAccessControl tests organization-level access control
func TestOrganizationAccessControl(t *testing.T) {
	t.Run("allows access with correct organization permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}

		mockPAT.On("IsAllowed", mock.Anything, mockSession, shared.ObjectOrganization, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)

		middleware := OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
	})

	t.Run("denies access without organization permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}

		mockPAT.On("IsAllowed", mock.Anything, mockSession, shared.ObjectOrganization, shared.ActionUpdate).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)

		middleware := OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, http.StatusNotFound, rec.Code)
		mockPAT.AssertExpectations(t)
	})

	t.Run("allows read access to public organization", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: true}

		mockPAT.On("IsAllowed", mock.Anything, mockSession, shared.ObjectOrganization, shared.ActionRead).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)

		middleware := OrganizationAccessControlMiddleware(shared.ObjectOrganization, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
	})
}

// TestProjectAccessControl tests project-level access control
func TestProjectAccessControl(t *testing.T) {
	t.Run("allows access with correct project permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, org.ID, "test-project").Return(project, nil)
		mockPAT.On("IsAllowedInProject", mock.Anything, mock.Anything, mockSession, shared.ObjectProject, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := ProjectAccessControlFactory(&mockProjectRepo)(shared.ObjectProject, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("denies access without project permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, org.ID, "test-project").Return(project, nil)
		mockPAT.On("IsAllowedInProject", mock.Anything, mock.Anything, mockSession, shared.ObjectProject, shared.ActionUpdate).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := ProjectAccessControlFactory(&mockProjectRepo)(shared.ObjectProject, shared.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		mockPAT.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("allows read access to public project", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
			IsPublic:       true,
		}

		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, org.ID, "test-project").Return(project, nil)
		mockPAT.On("IsAllowedInProject", mock.Anything, mock.Anything, mockSession, shared.ObjectProject, shared.ActionRead).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := ProjectAccessControlFactory(&mockProjectRepo)(shared.ObjectProject, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("uses project from context if already set", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		// Project already in context - should NOT call ReadBySlug
		mockPAT.On("IsAllowedInProject", mock.Anything, mock.Anything, mockSession, shared.ObjectProject, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := ProjectAccessControlFactory(&mockProjectRepo)(shared.ObjectProject, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
		mockProjectRepo.AssertNotCalled(t, "ReadBySlug", mock.Anything, mock.Anything)
	})
}

// TestAssetAccessControl tests the new asset-level access control
func TestAssetAccessControl(t *testing.T) {
	t.Run("allows access with correct asset permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", mock.Anything, mock.Anything, project.ID, "test-asset").Return(asset, nil)
		mockPAT.On("IsAllowedInAsset", mock.Anything, mock.Anything, mockSession, shared.ObjectAsset, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("denies access without asset permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", mock.Anything, mock.Anything, project.ID, "test-asset").Return(asset, nil)
		mockPAT.On("IsAllowedInAsset", mock.Anything, mock.Anything, mockSession, shared.ObjectAsset, shared.ActionUpdate).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
		mockPAT.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("allows read access to public asset", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
			IsPublic:  true,
		}

		mockAssetRepo.On("ReadBySlug", mock.Anything, mock.Anything, project.ID, "test-asset").Return(asset, nil)
		mockPAT.On("IsAllowedInAsset", mock.Anything, mock.Anything, mockSession, shared.ObjectAsset, shared.ActionRead).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("uses asset from context if already set", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		// Asset already in context - should NOT call ReadBySlug
		mockPAT.On("IsAllowedInAsset", mock.Anything, mock.Anything, mockSession, shared.ObjectAsset, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
		mockAssetRepo.AssertNotCalled(t, "ReadBySlug", mock.Anything, mock.Anything)
	})

	t.Run("returns error when asset not found", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}

		mockAssetRepo.On("ReadBySlug", mock.Anything, mock.Anything, project.ID, "nonexistent-asset").Return(models.Asset{}, errors.New("not found"))

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("nonexistent-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("returns error when RBAC check fails", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", mock.Anything, mock.Anything, project.ID, "test-asset").Return(asset, nil)
		mockPAT.On("IsAllowedInAsset", mock.Anything, mock.Anything, mockSession, shared.ObjectAsset, shared.ActionRead).Return(false, errors.New("rbac error"))

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
		mockPAT.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})
}

// TestMultiOrganizationMiddlewareRBAC tests the MultiOrganizationMiddlewareRBAC middleware
func TestMultiOrganizationMiddlewareRBAC(t *testing.T) {
	t.Run("returns 403 when oauth2 token is not valid", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("organization")
		ctx.SetParamValues("test-org")

		orgID := uuid.New()
		org := &models.Org{Model: models.Model{ID: orgID}, Slug: "test-org"}

		mockRBACProvider := mocks.RBACProvider{}
		mockOrgService := mocks.OrgService{}
		mockAccessControl := mocks.AccessControl{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{}, false)

		mockOrgService.On("ReadBySlug", mock.Anything, "test-org").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", orgID.String()).Return(&mockAccessControl)
		mockAccessControl.On("HasAccess", mock.Anything, mock.Anything).Return(false, shared.ErrOauth2TokenNotValidRedirectionRequired)

		shared.SetSession(ctx, mockSession)

		middleware := MultiOrganizationMiddlewareRBAC(&mockRBACProvider, &mockOrgService)

		err := middleware(func(ctx shared.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockAccessControl.AssertExpectations(t)
	})

	t.Run("returns 401 for generic HasAccess error on private org", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("organization")
		ctx.SetParamValues("test-org")

		orgID := uuid.New()
		org := &models.Org{Model: models.Model{ID: orgID}, Slug: "test-org"}

		mockRBACProvider := mocks.RBACProvider{}
		mockOrgService := mocks.OrgService{}
		mockAccessControl := mocks.AccessControl{}
		mockSession := shared.NewSession("user-id", dtos.SessionActorUser, []string{}, false)

		mockOrgService.On("ReadBySlug", mock.Anything, "test-org").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", orgID.String()).Return(&mockAccessControl)
		mockAccessControl.On("HasAccess", mock.Anything, mock.Anything).Return(false, errors.New("some auth error"))

		shared.SetSession(ctx, mockSession)

		middleware := MultiOrganizationMiddlewareRBAC(&mockRBACProvider, &mockOrgService)

		err := middleware(func(ctx shared.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockAccessControl.AssertExpectations(t)
	})
}

// TestAccessControlHierarchy tests that the access control respects the org -> project -> asset hierarchy
func TestAccessControlHierarchy(t *testing.T) {
	t.Run("org access allows project access", func(t *testing.T) {
		// This test demonstrates that having org-level access should allow project-level operations
		// (this is handled by the RBAC implementation itself, not the middleware)
		// The middleware just checks if the user has permission for the specific action

		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := shared.NewSession("org-admin", dtos.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, org.ID, "test-project").Return(project, nil)
		// The RBAC implementation should return true for org admins
		mockPAT.On("IsAllowedInProject", mock.Anything, mock.Anything, mockSession, shared.ObjectProject, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := ProjectAccessControlFactory(&mockProjectRepo)(shared.ObjectProject, shared.ActionRead)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		mockPAT.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("project access allows asset access", func(t *testing.T) {
		// This test demonstrates that having project-level access should allow asset-level operations
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := shared.NewSession("project-admin", dtos.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", mock.Anything, mock.Anything, project.ID, "test-asset").Return(asset, nil)
		// The RBAC implementation should return true for project admins
		mockPAT.On("IsAllowedInAsset", mock.Anything, mock.Anything, mockSession, shared.ObjectAsset, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := AssetAccessControlFactory(&mockAssetRepo)(shared.ObjectAsset, shared.ActionRead)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		mockPAT.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})
}
