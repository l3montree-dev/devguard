package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"gorm.io/gorm"
)

func TestMultiOrganizationMiddleware(t *testing.T) {
	t.Run("it should allow read requests, if the organization is public", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBACProvider := mocks.RBACProvider{}
		mockOrgService := mocks.OrgService{}
		mockRBAC := mocks.AccessControl{}

		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: true}

		mockOrgService.On("ReadBySlug", "organization-slug").Return(&org, nil)
		mockRBACProvider.On("GetDomainRBAC", org.ID.String()).Return(&mockRBAC)
		mockRBAC.On("HasAccess", auth.NoSession.GetUserID()).Return(false, nil)

		ctx.SetParamNames("organization")
		ctx.SetParamValues("organization-slug")
		ctx.Set("session", auth.NoSession)

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService, nil)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should deny access if the organization is not public and user has no access", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBACProvider := mocks.RBACProvider{}
		mockOrgService := mocks.OrgService{}
		mockRBAC := mocks.AccessControl{}

		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: false}
		session := auth.NewSession("user-id", []string{"test-role"})

		mockOrgService.On("ReadBySlug", "organization-slug").Return(&org, nil)
		mockRBACProvider.On("GetDomainRBAC", org.ID.String()).Return(&mockRBAC)
		mockRBAC.On("HasAccess", "user-id").Return(false, nil)

		ctx.SetParamNames("organization")
		ctx.SetParamValues("organization-slug")
		ctx.Set("session", session)

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService, nil)

		// act
		middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.Equal(t, http.StatusForbidden, rec.Code)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should return error if organization is not provided", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBACProvider := mocks.RBACProvider{}
		mockOrgService := mocks.OrgService{}

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService, nil)

		// act
		middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
	})

	t.Run("it should return error if organization is not found", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBACProvider := mocks.RBACProvider{}
		mockOrgService := mocks.OrgService{}

		mockOrgService.On("ReadBySlug", "organization-slug").Return(&models.Org{}, errors.New("not found"))

		ctx.SetParamNames("organization")
		ctx.SetParamValues("organization-slug")

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService, nil)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.NotNil(t, err)
		mockOrgService.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
	})
}
func TestAccessControlMiddleware(t *testing.T) {
	t.Run("it should allow access if user has the required role", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"test-role"})
		mockOrganization := models.Org{}

		userID := "user-id"
		obj := core.Object("test-object")
		act := core.Action("read")

		mockRBAC.On("IsAllowed", userID, obj, act).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := organizationAccessControlMiddleware(obj, act)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should deny access if user does not have the required role", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"test-role"})
		mockOrganization := models.Org{}

		userID := "user-id"
		obj := core.Object("test-object")
		act := core.Action("read")

		mockRBAC.On("IsAllowed", userID, obj, act).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := organizationAccessControlMiddleware(obj, act)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Error(t, err)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should allow access if organization is public and action is read", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"test-role"})
		mockOrganization := models.Org{
			IsPublic: true,
		}

		userID := "user-id"
		obj := core.Object("test-object")
		act := core.Action("read")

		mockRBAC.On("IsAllowed", userID, obj, act).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", &mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := organizationAccessControlMiddleware(obj, act)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should return error if unable to determine access", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession("user-id", []string{"test-role"})
		mockOrganization := models.Org{}

		userID := "user-id"
		obj := core.Object("test-object")
		act := core.Action("read")

		mockRBAC.On("IsAllowed", userID, obj, act).Return(false, errors.New("error"))

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", &mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := organizationAccessControlMiddleware(obj, act)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Error(t, err)
		mockRBAC.AssertExpectations(t)
	})
}

func TestAccessControlHierarchy(t *testing.T) {
	t.Run("comprehensive access control test for all levels", func(t *testing.T) {
		// This test verifies that access control works correctly at all levels:
		// Organization, Project, and Asset

		userID := "test-user"
		orgID := uuid.New()
		projectID := uuid.New()
		assetID := uuid.New()

		mockOrganization := models.Org{
			Model:    models.Model{ID: orgID},
			Slug:     "test-org",
			IsPublic: false,
		}

		mockProject := models.Project{
			Model:          models.Model{ID: projectID},
			Slug:           "test-project",
			OrganizationID: orgID,
			IsPublic:       false,
		}

		mockAsset := models.Asset{
			Model:     models.Model{ID: assetID},
			Slug:      "test-asset",
			ProjectID: projectID,
			IsPublic:  false,
		}

		testCases := []struct {
			name        string
			accessLevel string // "org", "project", "asset"
			userRole    core.Role
			object      core.Object
			action      core.Action
			shouldAllow bool
			description string
		}{
			// Organization-level tests
			{
				name:        "org_admin_can_read_org",
				accessLevel: "org",
				userRole:    core.RoleAdmin,
				object:      core.ObjectOrganization,
				action:      core.ActionRead,
				shouldAllow: true,
				description: "Organization admin should be able to read organization",
			},
			{
				name:        "org_member_can_read_org",
				accessLevel: "org",
				userRole:    core.RoleMember,
				object:      core.ObjectOrganization,
				action:      core.ActionRead,
				shouldAllow: true,
				description: "Organization member should be able to read organization",
			},
			{
				name:        "org_member_cannot_delete_org",
				accessLevel: "org",
				userRole:    core.RoleMember,
				object:      core.ObjectOrganization,
				action:      core.ActionDelete,
				shouldAllow: false,
				description: "Organization member should NOT be able to delete organization",
			},

			// Project-level tests
			{
				name:        "project_admin_can_update_project",
				accessLevel: "project",
				userRole:    core.RoleAdmin,
				object:      core.ObjectProject,
				action:      core.ActionUpdate,
				shouldAllow: true,
				description: "Project admin should be able to update project",
			},
			{
				name:        "project_member_can_read_project",
				accessLevel: "project",
				userRole:    core.RoleMember,
				object:      core.ObjectProject,
				action:      core.ActionRead,
				shouldAllow: true,
				description: "Project member should be able to read project",
			},
			{
				name:        "project_member_cannot_delete_project",
				accessLevel: "project",
				userRole:    core.RoleMember,
				object:      core.ObjectProject,
				action:      core.ActionDelete,
				shouldAllow: false,
				description: "Project member should NOT be able to delete project",
			},

			// Asset-level tests
			{
				name:        "asset_admin_can_update_asset",
				accessLevel: "asset",
				userRole:    core.RoleAdmin,
				object:      core.ObjectAsset,
				action:      core.ActionUpdate,
				shouldAllow: true,
				description: "Asset admin should be able to update asset",
			},
			{
				name:        "asset_member_can_read_asset",
				accessLevel: "asset",
				userRole:    core.RoleMember,
				object:      core.ObjectAsset,
				action:      core.ActionRead,
				shouldAllow: true,
				description: "Asset member should be able to read asset",
			},
			{
				name:        "asset_member_cannot_delete_asset",
				accessLevel: "asset",
				userRole:    core.RoleMember,
				object:      core.ObjectAsset,
				action:      core.ActionDelete,
				shouldAllow: false,
				description: "Asset member should NOT be able to delete asset",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				// arrange
				e := echo.New()
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				rec := httptest.NewRecorder()
				ctx := e.NewContext(req, rec)

				mockRBAC := mocks.AccessControl{}
				mockSession := auth.NewSession(userID, []string{string(tc.userRole)})

				// Set up the mock expectations based on access level
				switch tc.accessLevel {
				case "org":
					mockRBAC.On("IsAllowed", userID, tc.object, tc.action).Return(tc.shouldAllow, nil)
					ctx.Set("rbac", &mockRBAC)
					ctx.Set("session", mockSession)
					ctx.Set("organization", mockOrganization)

				case "project":
					mockRBAC.On("IsAllowedInProject", &mockProject, userID, tc.object, tc.action).Return(tc.shouldAllow, nil)
					ctx.Set("rbac", &mockRBAC)
					ctx.Set("session", mockSession)
					ctx.Set("organization", mockOrganization)
					ctx.Set("project", mockProject)

				case "asset":
					mockRBAC.On("IsAllowedInAsset", &mockAsset, userID, tc.object, tc.action).Return(tc.shouldAllow, nil)
					ctx.Set("rbac", &mockRBAC)
					ctx.Set("session", mockSession)
					ctx.Set("organization", mockOrganization)
					ctx.Set("project", mockProject)
					core.SetAsset(ctx, mockAsset)
				}

				// Create the appropriate middleware
				var middleware echo.MiddlewareFunc
				switch tc.accessLevel {
				case "org":
					middleware = organizationAccessControlMiddleware(tc.object, tc.action)
				case "project":
					mockProjectRepo := mocks.ProjectRepository{}
					mockProjectRepo.On("ReadBySlug", orgID, "test-project").Return(&mockProject, nil)
					projectMiddleware := projectAccessControlFactory(&mockProjectRepo)
					middleware = projectMiddleware(tc.object, tc.action)
					ctx.SetParamNames("projectSlug")
					ctx.SetParamValues("test-project")
				case "asset":
					mockAssetRepo := mocks.AssetRepository{}
					mockAssetRepo.On("ReadBySlug", projectID, "test-asset").Return(&mockAsset, nil)
					assetMiddleware := assetAccessControlFactory(&mockAssetRepo)
					middleware = assetMiddleware(tc.object, tc.action)
					ctx.SetParamNames("assetSlug")
					ctx.SetParamValues("test-asset")
				}

				// act
				err := middleware(func(ctx echo.Context) error {
					return ctx.JSON(http.StatusOK, "success")
				})(ctx)

				// assert
				if tc.shouldAllow {
					assert.NoError(t, err, tc.description)
					assert.Equal(t, http.StatusOK, rec.Code, tc.description)
				} else {
					assert.Error(t, err, tc.description)
					assert.Equal(t, http.StatusForbidden, rec.Code, tc.description)
				}

				mockRBAC.AssertExpectations(t)
			})
		}
	})
}

func TestPublicAccessControl(t *testing.T) {
	t.Run("public organizations allow read access to unauthenticated users", func(t *testing.T) {
		userID := "unauthenticated-user"
		orgID := uuid.New()

		mockOrganization := models.Org{
			Model:    models.Model{ID: orgID},
			Slug:     "public-org",
			IsPublic: true,
		}

		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockSession := auth.NewSession(userID, []string{})

		// User doesn't have direct access, but org is public
		mockRBAC.On("IsAllowed", userID, core.ObjectOrganization, core.ActionRead).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := organizationAccessControlMiddleware(core.ObjectOrganization, core.ActionRead)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err, "Public organization should allow read access")
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("public projects allow read access to unauthenticated users", func(t *testing.T) {
		userID := "unauthenticated-user"
		orgID := uuid.New()
		projectID := uuid.New()

		mockOrganization := models.Org{
			Model:    models.Model{ID: orgID},
			Slug:     "test-org",
			IsPublic: false,
		}

		mockProject := models.Project{
			Model:          models.Model{ID: projectID},
			Slug:           "public-project",
			OrganizationID: orgID,
			IsPublic:       true,
		}

		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockProjectRepo := mocks.ProjectRepository{}
		mockSession := auth.NewSession(userID, []string{})

		mockProjectRepo.On("ReadBySlug", orgID, "public-project").Return(&mockProject, nil)
		// User doesn't have direct access, but project is public
		mockRBAC.On("IsAllowedInProject", &mockProject, userID, core.ObjectProject, core.ActionRead).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)
		ctx.SetParamNames("projectSlug")
		ctx.SetParamValues("public-project")

		projectMiddleware := projectAccessControlFactory(&mockProjectRepo)
		middleware := projectMiddleware(core.ObjectProject, core.ActionRead)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err, "Public project should allow read access")
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockProjectRepo.AssertExpectations(t)
	})

	t.Run("public assets allow read access to unauthenticated users", func(t *testing.T) {
		userID := "unauthenticated-user"
		orgID := uuid.New()
		projectID := uuid.New()
		assetID := uuid.New()

		mockOrganization := models.Org{
			Model:    models.Model{ID: orgID},
			Slug:     "test-org",
			IsPublic: false,
		}

		mockProject := models.Project{
			Model:          models.Model{ID: projectID},
			Slug:           "test-project",
			OrganizationID: orgID,
			IsPublic:       false,
		}

		mockAsset := models.Asset{
			Model:     models.Model{ID: assetID},
			Slug:      "public-asset",
			ProjectID: projectID,
			IsPublic:  true,
		}

		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockRBAC := mocks.AccessControl{}
		mockAssetRepo := mocks.AssetRepository{}
		mockSession := auth.NewSession(userID, []string{})

		mockAssetRepo.On("ReadBySlug", projectID, "public-asset").Return(&mockAsset, nil)
		// User doesn't have direct access, but asset is public
		mockRBAC.On("IsAllowedInAsset", &mockAsset, userID, core.ObjectAsset, core.ActionRead).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)
		ctx.Set("project", mockProject)
		ctx.SetParamNames("assetSlug")
		ctx.SetParamValues("public-asset")

		assetAccessMiddleware := assetAccessControlFactory(&mockAssetRepo)
		middleware := assetAccessMiddleware(core.ObjectAsset, core.ActionRead)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err, "Public asset should allow read access")
		assert.Equal(t, http.StatusOK, rec.Code)
		mockRBAC.AssertExpectations(t)
		mockAssetRepo.AssertExpectations(t)
	})
}
func TestNeededScope(t *testing.T) {
	t.Run("it should allow access if user has all required scopes", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockSession := auth.NewSession("user-id", []string{"scope1", "scope2", "scope3"})
		ctx.Set("session", mockSession)

		middleware := neededScope([]string{"scope1", "scope2"})

		handler := func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		}
		// act
		handleWithMiddleware := middleware(handler)

		err := handleWithMiddleware(ctx)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("it should deny access if user does not have all required scopes", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockSession := auth.NewSession("user-id", []string{"scope1"})
		ctx.Set("session", mockSession)

		middleware := neededScope([]string{"scope1", "scope2"})

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.Error(t, err)

		// should be an echo.HTTPError
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.Code)
	})

	t.Run("it should deny access if user has no scopes", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockSession := auth.NewSession("user-id", []string{})
		ctx.Set("session", mockSession)

		middleware := neededScope([]string{"scope1"})

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.Error(t, err)

		// should be an echo.HTTPError
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, http.StatusForbidden, httpErr.Code)
	})

	t.Run("it should allow access if no scopes are required", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockSession := auth.NewSession("user-id", []string{"scope1"})
		ctx.Set("session", mockSession)

		middleware := neededScope([]string{})

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
	})
}

func TestAssetVersionMiddleware(t *testing.T) {
	t.Run("it should update LastAccessedAt timestamp when asset version is found", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockAssetVersionRepository := mocks.NewAssetVersionRepository(t)

		assetID := uuid.New()
		assetVersionSlug := "v1.0.0"
		asset := models.Asset{
			Model: models.Model{ID: assetID},
			Name:  "test-asset",
		}
		assetVersion := models.AssetVersion{
			Name:    "v1.0.0",
			AssetID: assetID,
			Slug:    assetVersionSlug,
		}

		// Set up context with asset and parameters
		core.SetAsset(ctx, asset)
		ctx.SetParamNames("assetVersionSlug")
		ctx.SetParamValues(assetVersionSlug)

		// Mock the repository calls
		mockAssetVersionRepository.On("ReadBySlug", assetID, assetVersionSlug).Return(assetVersion, nil)
		mockAssetVersionRepository.On("Save", (*gorm.DB)(nil), mock.MatchedBy(func(av *models.AssetVersion) bool {
			// Verify that the asset version has the correct basic fields
			if av.Name != "v1.0.0" || av.AssetID != assetID || av.Slug != assetVersionSlug {
				return false
			}
			// Verify that LastAccessedAt is set and is recent (should not be zero time)
			return !av.LastAccessedAt.IsZero() && time.Since(av.LastAccessedAt) < time.Minute
		})).Return(nil)

		middleware := assetVersionMiddleware(mockAssetVersionRepository)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// Wait a bit for the goroutine to complete
		time.Sleep(100 * time.Millisecond)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Verify that the asset version was set in context
		setAssetVersion := core.GetAssetVersion(ctx)
		assert.Equal(t, assetVersion.Name, setAssetVersion.Name)
		assert.Equal(t, assetVersion.Slug, setAssetVersion.Slug)

		mockAssetVersionRepository.AssertExpectations(t)
	})

	t.Run("it should handle default asset version gracefully", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockAssetVersionRepository := mocks.NewAssetVersionRepository(t)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
			Name:  "test-asset",
		}

		// Set up context with asset and default slug
		core.SetAsset(ctx, asset)
		ctx.SetParamNames("assetVersionSlug")
		ctx.SetParamValues("default")

		// Mock the repository to return an error for default slug
		mockAssetVersionRepository.On("ReadBySlug", assetID, "default").Return(models.AssetVersion{}, errors.New("not found"))

		middleware := assetVersionMiddleware(mockAssetVersionRepository)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Verify that an empty asset version was set in context for default
		setAssetVersion := core.GetAssetVersion(ctx)
		assert.Equal(t, "", setAssetVersion.Name)

		mockAssetVersionRepository.AssertExpectations(t)
	})

	t.Run("it should return 404 when asset version is not found", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockAssetVersionRepository := mocks.NewAssetVersionRepository(t)

		assetID := uuid.New()
		assetVersionSlug := "nonexistent"
		asset := models.Asset{
			Model: models.Model{ID: assetID},
			Name:  "test-asset",
		}

		// Set up context with asset and parameters
		core.SetAsset(ctx, asset)
		ctx.SetParamNames("assetVersionSlug")
		ctx.SetParamValues(assetVersionSlug)

		// Mock the repository to return an error
		mockAssetVersionRepository.On("ReadBySlug", assetID, assetVersionSlug).Return(models.AssetVersion{}, errors.New("not found"))

		middleware := assetVersionMiddleware(mockAssetVersionRepository)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NotNil(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 404, httpErr.Code)
		assert.Equal(t, "could not find asset version", httpErr.Message)

		mockAssetVersionRepository.AssertExpectations(t)
	})

	t.Run("it should return 400 when asset version slug is missing", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)

		mockAssetVersionRepository := mocks.NewAssetVersionRepository(t)

		assetID := uuid.New()
		asset := models.Asset{
			Model: models.Model{ID: assetID},
			Name:  "test-asset",
		}

		// Set up context with asset but no asset version slug parameter
		core.SetAsset(ctx, asset)
		// Don't set param names/values to simulate missing slug

		middleware := assetVersionMiddleware(mockAssetVersionRepository)

		// act
		err := middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx)

		// assert
		assert.NotNil(t, err)
		httpErr, ok := err.(*echo.HTTPError)
		assert.True(t, ok)
		assert.Equal(t, 400, httpErr.Code)
		assert.Equal(t, "invalid asset version slug", httpErr.Message)

		mockAssetVersionRepository.AssertExpectations(t)
	})
}
