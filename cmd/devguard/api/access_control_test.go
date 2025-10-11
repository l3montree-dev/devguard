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

package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// TestOrganizationAccessControl tests organization-level access control
func TestOrganizationAccessControl(t *testing.T) {
	t.Run("allows access with correct organization permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}

		mockRBAC.On("IsAllowed", "user-id", core.ObjectOrganization, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)

		middleware := organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("denies access without organization permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}

		mockRBAC.On("IsAllowed", "user-id", core.ObjectOrganization, core.ActionUpdate).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)

		middleware := organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("allows read access to public organization", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: true}

		mockRBAC.On("IsAllowed", "user-id", core.ObjectOrganization, core.ActionRead).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)

		middleware := organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
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

		mockRBAC := mocks.AccessControl{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockProjectRepo.On("ReadBySlug", org.ID, "test-project").Return(project, nil)
		mockRBAC.On("IsAllowedInProject", &project, "user-id", core.ObjectProject, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := projectAccessControlFactory(&mockProjectRepo)(core.ObjectProject, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("denies access without project permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockProjectRepo.On("ReadBySlug", org.ID, "test-project").Return(project, nil)
		mockRBAC.On("IsAllowedInProject", &project, "user-id", core.ObjectProject, core.ActionUpdate).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := projectAccessControlFactory(&mockProjectRepo)(core.ObjectProject, core.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		mockRBAC.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("allows read access to public project", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
			IsPublic:       true,
		}

		mockProjectRepo.On("ReadBySlug", org.ID, "test-project").Return(project, nil)
		mockRBAC.On("IsAllowedInProject", &project, "user-id", core.ObjectProject, core.ActionRead).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := projectAccessControlFactory(&mockProjectRepo)(core.ObjectProject, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("uses project from context if already set", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		// Project already in context - should NOT call ReadBySlug
		mockRBAC.On("IsAllowedInProject", &project, "user-id", core.ObjectProject, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)
		ctx.Set("project", project)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := projectAccessControlFactory(&mockProjectRepo)(core.ObjectProject, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
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

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", project.ID, "test-asset").Return(asset, nil)
		mockRBAC.On("IsAllowedInAsset", &asset, "user-id", core.ObjectAsset, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("denies access without asset permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", project.ID, "test-asset").Return(asset, nil)
		mockRBAC.On("IsAllowedInAsset", &asset, "user-id", core.ObjectAsset, core.ActionUpdate).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.Code)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("allows read access to public asset", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
			IsPublic:  true,
		}

		mockAssetRepo.On("ReadBySlug", project.ID, "test-asset").Return(asset, nil)
		mockRBAC.On("IsAllowedInAsset", &asset, "user-id", core.ObjectAsset, core.ActionRead).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})

	t.Run("uses asset from context if already set", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		// Asset already in context - should NOT call ReadBySlug
		mockRBAC.On("IsAllowedInAsset", &asset, "user-id", core.ObjectAsset, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.Set("asset", asset)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertNotCalled(t, "ReadBySlug", mock.Anything, mock.Anything)
	})

	t.Run("returns error when asset not found", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}

		mockAssetRepo.On("ReadBySlug", project.ID, "nonexistent-asset").Return(models.Asset{}, errors.New("not found"))

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("nonexistent-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionRead)

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

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("user-id", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", project.ID, "test-asset").Return(asset, nil)
		mockRBAC.On("IsAllowedInAsset", &asset, "user-id", core.ObjectAsset, core.ActionRead).Return(false, errors.New("rbac error"))

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusInternalServerError, httpErr.Code)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
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

		mockRBAC := mocks.AccessControl{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := auth.NewSession("org-admin", []string{"manage"})
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockProjectRepo.On("ReadBySlug", org.ID, "test-project").Return(project, nil)
		// The RBAC implementation should return true for org admins
		mockRBAC.On("IsAllowedInProject", &project, "org-admin", core.ObjectProject, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", org)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("test-project")

		middleware := projectAccessControlFactory(&mockProjectRepo)(core.ObjectProject, core.ActionRead)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		mockRBAC.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("project access allows asset access", func(t *testing.T) {
		// This test demonstrates that having project-level access should allow asset-level operations
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession("project-admin", []string{"manage"})
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockAssetRepo.On("ReadBySlug", project.ID, "test-asset").Return(asset, nil)
		// The RBAC implementation should return true for project admins
		mockRBAC.On("IsAllowedInAsset", &asset, "project-admin", core.ObjectAsset, core.ActionRead).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("project", project)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("test-asset")

		middleware := assetAccessControlFactory(&mockAssetRepo)(core.ObjectAsset, core.ActionRead)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})
}
