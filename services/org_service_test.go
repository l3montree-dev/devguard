package services

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

func TestServiceCreate(t *testing.T) {
	t.Run("should fail if the repository cannot create the organization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		h := NewOrgService(organizationRepository, nil)

		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}
	})
	t.Run("should fail if the repository cannot create the organization due to a duplicate organization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong duplicate key value"))

		h := NewOrgService(organizationRepository, nil)

		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})

	t.Run("should succeed if everything goes right", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		h := NewOrgService(organizationRepository, rbacProvider)

		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err != nil {
			t.Fail()
		}
	})
	t.Run("should return an error if the bootstrapping of the organization fails somehow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)

		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})

	//------------------------------------------------------------Testing Bootstrap Function from here on-----------------------------------------------------------------------------
	t.Run("should fail if grant Role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)

		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if inheritRole with a member as provider for the permissions returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, shared.RoleAdmin).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, shared.RoleMember).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)

		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if inheritRole with an admin as provider for the permissions returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, shared.RoleAdmin).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)
		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with organizations as the object and owner as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleOwner, shared.ObjectOrganization, mock.Anything).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)
		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with organizations as the object and admin as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleOwner, shared.ObjectOrganization, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleAdmin, shared.ObjectOrganization, mock.Anything).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)
		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with project as the object and admin as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleOwner, shared.ObjectOrganization, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleAdmin, shared.ObjectOrganization, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleAdmin, shared.ObjectProject, mock.Anything).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)
		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with organizations as the object and member as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccessControl(t)
		authSession := mocks.NewAuthSession(t)
		authSession.On("GetUserID").Return("")

		shared.SetSession(ctx, authSession)

		rbacProvider := mocks.NewRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleOwner, shared.ObjectOrganization, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleAdmin, shared.ObjectOrganization, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleAdmin, shared.ObjectProject, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", shared.RoleMember, shared.ObjectOrganization, mock.Anything).Return(fmt.Errorf("something went wrong"))

		h := NewOrgService(organizationRepository, rbacProvider)
		err := h.CreateOrganization(ctx, &models.Org{Name: "cool org", Slug: "cool-org"})

		if err == nil {
			t.Fail()
		}

	})
}
