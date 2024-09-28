package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/internal/auth"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func TestMultiTenantMiddleware(t *testing.T) {
	t.Run("it should allow read requests, if the organization is public", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockRBACProvider := mocks.AccesscontrolRBACProvider{}
		mockOrgRepo := mocks.ApiOrgRepository{}
		mockRBAC := mocks.AccesscontrolAccessControl{}

		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: true}

		mockOrgRepo.On("ReadBySlug", "tenant-slug").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", org.ID.String()).Return(&mockRBAC)
		mockRBAC.On("HasAccess", auth.NoSession.GetUserID()).Return(false)

		c.SetParamNames("tenant")
		c.SetParamValues("tenant-slug")
		c.Set("session", auth.NoSession)

		middleware := multiTenantMiddleware(&mockRBACProvider, &mockOrgRepo)

		// act
		err := middleware(func(c echo.Context) error {
			return c.JSON(http.StatusOK, "success")
		})(c)

		// assert
		assert.NoError(t, err)
		assert.Equal(t, http.StatusOK, rec.Code)
		mockOrgRepo.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should deny access if the organization is not public and user has no access", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockRBACProvider := mocks.AccesscontrolRBACProvider{}
		mockOrgRepo := mocks.ApiOrgRepository{}
		mockRBAC := mocks.AccesscontrolAccessControl{}

		org := models.Org{Model: models.Model{ID: uuid.New()}, IsPublic: false}
		session := auth.NewSession("user-id")

		mockOrgRepo.On("ReadBySlug", "tenant-slug").Return(org, nil)
		mockRBACProvider.On("GetDomainRBAC", org.ID.String()).Return(&mockRBAC)
		mockRBAC.On("HasAccess", "user-id").Return(false)

		c.SetParamNames("tenant")
		c.SetParamValues("tenant-slug")
		c.Set("session", session)

		middleware := multiTenantMiddleware(&mockRBACProvider, &mockOrgRepo)

		// act
		middleware(func(c echo.Context) error {
			return c.JSON(http.StatusOK, "success")
		})(c) // nolint:errcheck

		// assert
		assert.Equal(t, http.StatusForbidden, rec.Code)
		mockOrgRepo.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
		mockRBAC.AssertExpectations(t)
	})

	t.Run("it should return error if tenant is not provided", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockRBACProvider := mocks.AccesscontrolRBACProvider{}
		mockOrgRepo := mocks.ApiOrgRepository{}

		middleware := multiTenantMiddleware(&mockRBACProvider, &mockOrgRepo)

		// act
		middleware(func(c echo.Context) error {
			return c.JSON(http.StatusOK, "success")
		})(c) // nolint:errcheck

		assert.Equal(t, http.StatusBadRequest, rec.Code)
		mockOrgRepo.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
	})

	t.Run("it should return error if tenant is not found", func(t *testing.T) {
		// arrange
		e := echo.New()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		c := e.NewContext(req, rec)

		mockRBACProvider := mocks.AccesscontrolRBACProvider{}
		mockOrgRepo := mocks.ApiOrgRepository{}

		mockOrgRepo.On("ReadBySlug", "tenant-slug").Return(models.Org{}, errors.New("not found"))

		c.SetParamNames("tenant")
		c.SetParamValues("tenant-slug")

		middleware := multiTenantMiddleware(&mockRBACProvider, &mockOrgRepo)

		// act
		middleware(func(c echo.Context) error {
			return c.JSON(http.StatusOK, "success")
		})(c) // nolint:errcheck

		// assert
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		mockOrgRepo.AssertExpectations(t)
		mockRBACProvider.AssertExpectations(t)
	})
}
