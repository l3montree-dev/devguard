package services

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/ory/client-go"

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

func TestFetchMembersOfOrganization(t *testing.T) {
	t.Run("Should fail if GetAllMembers returns an error", func(t *testing.T) {

		accesscontrol := mocks.NewAccessControl(t)
		accesscontrol.On("GetAllMembersOfOrganization", mock.Anything).Return([]string{}, fmt.Errorf("Something went wrong"))

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{})
		shared.SetRBAC(ctx, accesscontrol)

		_, err := shared.FetchMembersOfOrganization(ctx)
		if err == nil {

			t.Fail()
		}

	})
	t.Run("Should fail if ListUser returns an error", func(t *testing.T) {
		emptyList := []client.Identity{}

		accesscontrol := mocks.NewAccessControl(t)
		accesscontrol.On("GetAllMembersOfOrganization", mock.Anything).Return([]string{"abc"}, nil)

		adminClient := mocks.NewAdminClient(t)
		adminClient.On("ListUser", mock.Anything).Return(emptyList, fmt.Errorf("Something went wrong"))

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{})
		shared.SetRBAC(ctx, accesscontrol)
		shared.SetAuthAdminClient(ctx, adminClient)

		_, err := shared.FetchMembersOfOrganization(ctx)
		if err == nil {

			t.Fail()
		}

	})
	t.Run("should NOT call ListUser if the GetAllMembersOfOrganization returns an empty array succeed if everything works as expected with empty lists", func(t *testing.T) {
		accesscontrol := mocks.NewAccessControl(t)
		accesscontrol.On("GetAllMembersOfOrganization", mock.Anything).Return([]string{}, nil)

		adminClient := mocks.NewAdminClient(t)

		// THIS SHOULD NOT BE CALLED
		// adminClient.On("ListUser", mock.Anything).Return(emptyList, nil)

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("GetUsers", mock.Anything).Return([]dtos.UserDTO{})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{})
		shared.SetRBAC(ctx, accesscontrol)
		shared.SetAuthAdminClient(ctx, adminClient)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		_, err := shared.FetchMembersOfOrganization(ctx)
		if err != nil {
			t.Fail()
		}
	})

	t.Run("should succeed if everything works as expected", func(t *testing.T) {
		emptyList := []client.Identity{}

		accesscontrol := mocks.NewAccessControl(t)
		accesscontrol.On("GetAllMembersOfOrganization", mock.Anything).Return([]string{"abc"}, nil)

		adminClient := mocks.NewAdminClient(t)
		adminClient.On("ListUser", mock.Anything).Return(emptyList, nil)

		thirdPartyIntegration := mocks.NewIntegrationAggregate(t)
		thirdPartyIntegration.On("GetUsers", mock.Anything).Return([]dtos.UserDTO{})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{})
		shared.SetRBAC(ctx, accesscontrol)
		shared.SetAuthAdminClient(ctx, adminClient)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		_, err := shared.FetchMembersOfOrganization(ctx)
		if err != nil {

			t.Fail()
		}
	})
}
