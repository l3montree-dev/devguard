// Copyright (C) 2025 l3montree GmbH
//
// This program is free software: you can redistribute it and/or modify
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

// TestOrganizationAccessControl tests organization-level access control.
// OrganizationAccessControlMiddleware assumes ResourceFetchMiddleware already
// resolved the org/rbac/actor scope into the context - these tests pre-set
// them directly rather than going through the resolver.
func TestOrganizationAccessControl(t *testing.T) {
	t.Run("allows access with correct organization permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}

		mockPAT.On("IsAllowed", mock.Anything, mockSession, shared.ObjectOrganization, shared.ActionRead, mock.Anything).Return(true, nil)

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
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}

		mockPAT.On("IsAllowed", mock.Anything, mockSession, shared.ObjectOrganization, shared.ActionUpdate, mock.Anything).Return(false, nil)

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
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: true}

		mockPAT.On("IsAllowed", mock.Anything, mockSession, shared.ObjectOrganization, shared.ActionRead, mock.Anything).Return(false, nil)

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

// TestProjectAccessControl tests project-level access control.
// ProjectAccessControl assumes ResourceFetchMiddleware already resolved
// the project into the context - it never fetches anything itself.
func TestProjectAccessControl(t *testing.T) {
	t.Run("allows access with correct project permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockPAT.On("IsAllowedInProject", mock.Anything, &project, mockSession, shared.ObjectProject, shared.ActionRead, mock.Anything).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)

		middleware := ProjectAccessControl(shared.ObjectProject, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
	})

	t.Run("denies access without project permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		mockPAT.On("IsAllowedInProject", mock.Anything, &project, mockSession, shared.ObjectProject, shared.ActionUpdate, mock.Anything).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)

		middleware := ProjectAccessControl(shared.ObjectProject, shared.ActionUpdate)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.Error(t, err)
		mockPAT.AssertExpectations(t)
	})

	t.Run("allows read access to public project", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
			IsPublic:       true,
		}

		mockPAT.On("IsAllowedInProject", mock.Anything, &project, mockSession, shared.ObjectProject, shared.ActionRead, mock.Anything).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)

		middleware := ProjectAccessControl(shared.ObjectProject, shared.ActionRead)

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

// TestAssetAccessControl tests asset-level access control.
// AssetAccessControl assumes ResourceFetchMiddleware already resolved
// the asset into the context - it never fetches anything itself.
func TestAssetAccessControl(t *testing.T) {
	t.Run("allows access with correct asset permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockPAT.On("IsAllowedInAsset", mock.Anything, &asset, mockSession, shared.ObjectAsset, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset)

		middleware := AssetAccessControl(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
	})

	t.Run("denies access without asset permissions", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockPAT.On("IsAllowedInAsset", mock.Anything, &asset, mockSession, shared.ObjectAsset, shared.ActionUpdate).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset)

		middleware := AssetAccessControl(shared.ObjectAsset, shared.ActionUpdate)

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
	})

	t.Run("allows read access to public asset", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
			IsPublic:  true,
		}

		mockPAT.On("IsAllowedInAsset", mock.Anything, &asset, mockSession, shared.ObjectAsset, shared.ActionRead).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset)

		middleware := AssetAccessControl(shared.ObjectAsset, shared.ActionRead)

		// Act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockPAT.AssertExpectations(t)
	})

	t.Run("returns error when RBAC check fails", func(t *testing.T) {
		// Arrange
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		mockPAT.On("IsAllowedInAsset", mock.Anything, &asset, mockSession, shared.ObjectAsset, shared.ActionRead).Return(false, errors.New("rbac error"))

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset)

		middleware := AssetAccessControl(shared.ObjectAsset, shared.ActionRead)

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
	})
}

// TestMultiOrganizationMiddlewareRBAC tests the MultiOrganizationMiddlewareRBAC
// middleware. It assumes ResourceFetchMiddleware already resolved the org,
// rbac and actor scope into the context - it never fetches anything itself.
func TestMultiOrganizationMiddlewareRBAC(t *testing.T) {
	t.Run("returns 403 when oauth2 token is not valid", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		org := models.Org{Model: models.Model{ID: uuid.New()}, Slug: "test-org"}
		mockAccessControl := mocks.AccessControl{}
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{}, false)

		mockAccessControl.On("HasAccess", mock.Anything, mockSession, mock.Anything).Return(false, shared.ErrOauth2TokenNotValidRedirectionRequired)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetRBAC(ctx, &mockAccessControl)

		middleware := MultiOrganizationMiddlewareRBAC()

		err := middleware(func(ctx shared.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		mockAccessControl.AssertExpectations(t)
	})

	t.Run("returns 401 for generic HasAccess error on private org", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		org := models.Org{Model: models.Model{ID: uuid.New()}, Slug: "test-org"}
		mockAccessControl := mocks.AccessControl{}
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{}, false)

		mockAccessControl.On("HasAccess", mock.Anything, mockSession, mock.Anything).Return(false, errors.New("some auth error"))

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetRBAC(ctx, &mockAccessControl)

		middleware := MultiOrganizationMiddlewareRBAC()

		err := middleware(func(ctx shared.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		mockAccessControl.AssertExpectations(t)
	})

	t.Run("allows public org read when access is denied", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		org := models.Org{Model: models.Model{ID: uuid.New()}, Slug: "test-org", IsPublic: true}
		mockAccessControl := mocks.AccessControl{}
		mockSession := shared.NewSession("user-id", shared.SessionActorUser, []string{}, false)

		mockAccessControl.On("HasAccess", mock.Anything, mockSession, mock.Anything).Return(false, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetRBAC(ctx, &mockAccessControl)

		middleware := MultiOrganizationMiddlewareRBAC()

		err := middleware(func(ctx shared.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, shared.IsPublicRequest(ctx))
		mockAccessControl.AssertExpectations(t)
	})
}

// TestResourceFetchMiddleware tests the single entity-resolution middleware:
// it resolves org/project/asset by URL slug (once each) and the session's own
// actor scope by owner ID, reusing the path-resolved entity when it's the same
// row as the token's own scope.
func TestResourceFetchMiddleware(t *testing.T) {
	t.Run("resolves org, project and asset by slug and reuses the path-resolved project as actor scope", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("organization", "projectSlug")
		ctx.SetParamValues("test-org", "test-project")

		orgID := uuid.New()
		org := &models.Org{Model: models.Model{ID: orgID}, Slug: "test-org"}
		project := models.Project{Model: models.Model{ID: uuid.New()}, Slug: "test-project", OrganizationID: orgID}

		mockOrgService := mocks.OrgService{}
		mockRBACProvider := mocks.RBACProvider{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockAssetRepo := mocks.AssetRepository{}
		mockAccessControl := mocks.AccessControl{}

		mockOrgService.On("ReadBySlug", mock.Anything, "test-org").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", orgID.String()).Return(&mockAccessControl)
		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, orgID, "test-project").Return(project, nil)

		// project-scoped session whose owner ID matches the path-resolved project -
		// resolveActorScope must reuse it, never calling Read for the actor scope.
		session := shared.NewSession(project.ID.String(), shared.SessionActorProject, nil, false)
		shared.SetSession(ctx, session)

		middleware := ResourceFetchMiddleware(&mockRBACProvider, &mockOrgService, &mockProjectRepo, &mockAssetRepo)

		var gotScope shared.ActorScope
		err := middleware(func(ctx echo.Context) error {
			gotScope = shared.GetActorScope(ctx)
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, org.ID, shared.GetOrg(ctx).ID)
		assert.Equal(t, project.ID, shared.GetProject(ctx).ID)
		if assert.NotNil(t, gotScope.Project) {
			assert.Equal(t, project.ID, gotScope.Project.ID)
		}
		mockProjectRepo.AssertNotCalled(t, "Read", mock.Anything, mock.Anything, mock.Anything)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("fetches the actor's own project separately when it differs from the path-resolved project", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("organization", "projectSlug")
		ctx.SetParamValues("test-org", "test-project")

		orgID := uuid.New()
		org := &models.Org{Model: models.Model{ID: orgID}, Slug: "test-org"}
		pathProject := models.Project{Model: models.Model{ID: uuid.New()}, Slug: "test-project", OrganizationID: orgID}
		ownProject := models.Project{Model: models.Model{ID: uuid.New()}, Slug: "own-project", OrganizationID: orgID}

		mockOrgService := mocks.OrgService{}
		mockRBACProvider := mocks.RBACProvider{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockAssetRepo := mocks.AssetRepository{}
		mockAccessControl := mocks.AccessControl{}

		mockOrgService.On("ReadBySlug", mock.Anything, "test-org").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", orgID.String()).Return(&mockAccessControl)
		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, orgID, "test-project").Return(pathProject, nil)
		// a different project than the one in the URL - must be fetched separately
		mockProjectRepo.On("Read", mock.Anything, mock.Anything, ownProject.ID).Return(ownProject, nil)

		session := shared.NewSession(ownProject.ID.String(), shared.SessionActorProject, nil, false)
		shared.SetSession(ctx, session)

		middleware := ResourceFetchMiddleware(&mockRBACProvider, &mockOrgService, &mockProjectRepo, &mockAssetRepo)

		var gotScope shared.ActorScope
		err := middleware(func(ctx echo.Context) error {
			gotScope = shared.GetActorScope(ctx)
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		// the URL-resolved project and the token's own project must never be conflated
		assert.Equal(t, pathProject.ID, shared.GetProject(ctx).ID)
		if assert.NotNil(t, gotScope.Project) {
			assert.Equal(t, ownProject.ID, gotScope.Project.ID)
		}
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("returns 404 when the project cannot be found", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("organization", "projectSlug")
		ctx.SetParamValues("test-org", "missing-project")

		orgID := uuid.New()
		org := &models.Org{Model: models.Model{ID: orgID}, Slug: "test-org"}

		mockOrgService := mocks.OrgService{}
		mockRBACProvider := mocks.RBACProvider{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockAssetRepo := mocks.AssetRepository{}
		mockAccessControl := mocks.AccessControl{}

		mockOrgService.On("ReadBySlug", mock.Anything, "test-org").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", orgID.String()).Return(&mockAccessControl)
		mockProjectRepo.On("ReadBySlug", mock.Anything, mock.Anything, orgID, "missing-project").Return(models.Project{}, errors.New("not found"))

		shared.SetSession(ctx, shared.NewSession("user-id", shared.SessionActorUser, nil, false))

		middleware := ResourceFetchMiddleware(&mockRBACProvider, &mockOrgService, &mockProjectRepo, &mockAssetRepo)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.Error(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusNotFound, httpErr.Code)
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
		mockSession := shared.NewSession("org-admin", shared.SessionActorUser, []string{"manage"}, false)
		org := models.Org{Model: models.Model{ID: uuid.New()}}
		project := models.Project{
			Model:          models.Model{ID: uuid.New()},
			Slug:           "test-project",
			OrganizationID: org.ID,
		}

		// The RBAC implementation should return true for org admins
		mockPAT.On("IsAllowedInProject", mock.Anything, &project, mockSession, shared.ObjectProject, shared.ActionRead, mock.Anything).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetOrg(ctx, org)
		shared.SetProject(ctx, project)

		middleware := ProjectAccessControl(shared.ObjectProject, shared.ActionRead)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		mockPAT.AssertExpectations(t)
	})

	t.Run("project access allows asset access", func(t *testing.T) {
		// This test demonstrates that having project-level access should allow asset-level operations
		e := echo.New()
		req := httptest.NewRequest("GET", "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockPAT := mocks.AccessControl{}
		shared.SetRBAC(ctx, &mockPAT)
		mockSession := shared.NewSession("project-admin", shared.SessionActorUser, []string{"manage"}, false)
		project := models.Project{Model: models.Model{ID: uuid.New()}}
		asset := models.Asset{
			Model:     models.Model{ID: uuid.New()},
			Slug:      "test-asset",
			ProjectID: project.ID,
		}

		// The RBAC implementation should return true for project admins
		mockPAT.On("IsAllowedInAsset", mock.Anything, &asset, mockSession, shared.ObjectAsset, shared.ActionRead).Return(true, nil)

		shared.SetSession(ctx, mockSession)
		shared.SetProject(ctx, project)
		shared.SetAsset(ctx, asset)

		middleware := AssetAccessControl(shared.ObjectAsset, shared.ActionRead)

		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		assert.NoError(t, err)
		mockPAT.AssertExpectations(t)
	})
}
