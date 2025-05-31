package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/accesscontrol"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
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

		mockOrgService.On("ReadBySlug", "organization-slug").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", org.ID.String()).Return(&mockRBAC)
		mockRBAC.On("HasAccess", auth.NoSession.GetUserID()).Return(false)

		ctx.SetParamNames("organization")
		ctx.SetParamValues("organization-slug")
		ctx.Set("session", auth.NoSession)

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService)

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

		mockOrgService.On("ReadBySlug", "organization-slug").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", org.ID.String()).Return(&mockRBAC)
		mockRBAC.On("HasAccess", "user-id").Return(false)

		ctx.SetParamNames("organization")
		ctx.SetParamValues("organization-slug")
		ctx.Set("session", session)

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService)

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

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService)

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

		mockOrgService.On("ReadBySlug", "organization-slug").Return(models.Org{}, errors.New("not found"))

		ctx.SetParamNames("organization")
		ctx.SetParamValues("organization-slug")

		middleware := multiOrganizationMiddleware(&mockRBACProvider, &mockOrgService)

		// act
		middleware(func(ctx echo.Context) error {
			return ctx.JSON(http.StatusOK, "success")
		})(ctx) // nolint:errcheck

		// assert
		assert.Equal(t, http.StatusBadRequest, rec.Code)
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
		obj := accesscontrol.Object("test-object")
		act := accesscontrol.Action("read")

		mockRBAC.On("IsAllowed", userID, string(obj), act).Return(true, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := accessControlMiddleware(obj, act)

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
		obj := accesscontrol.Object("test-object")
		act := accesscontrol.Action("read")

		mockRBAC.On("IsAllowed", userID, string(obj), act).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := accessControlMiddleware(obj, act)

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
		obj := accesscontrol.Object("test-object")
		act := accesscontrol.Action("read")

		mockRBAC.On("IsAllowed", userID, string(obj), act).Return(false, nil)

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", &mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := accessControlMiddleware(obj, act)

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
		obj := accesscontrol.Object("test-object")
		act := accesscontrol.Action("read")

		mockRBAC.On("IsAllowed", userID, string(obj), act).Return(false, errors.New("error"))

		ctx.Set("rbac", &mockRBAC)
		ctx.Set("session", &mockSession)
		ctx.Set("organization", mockOrganization)

		middleware := accessControlMiddleware(obj, act)

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
