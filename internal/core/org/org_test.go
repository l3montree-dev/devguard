package org_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/mock"
)

// Test function for Create and bootstrap from org_controller
func TestCreate(t *testing.T) {
	t.Run("Should fail if a context with wrong parameters is provided", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString("fantasy"))

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		h := org.NewHttpController(nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("Should fail if the context is in the wrong format", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", nil)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		core.SetOrg(ctx, models.Org{Name: "fantasy", Slug: "fantasy"})

		h := org.NewHttpController(nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if the slug is empty after the slug.make function", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "//"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		h := org.NewHttpController(nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if the repository cannot create the organization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		h := org.NewHttpController(organizationRepository, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if the repository cannot create the organization due to a duplicate organization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong duplicate key value"))

		h := org.NewHttpController(organizationRepository, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})

	t.Run("should succeed if everything goes right", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", mock.Anything, mock.Anything, mock.Anything).Return(nil)

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err != nil {
			t.Fail()
		}

	})
	t.Run("should return an error if the bootstrapping of the organization fails somehow", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", mock.Anything, mock.Anything, mock.Anything).Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
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

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(fmt.Errorf("Something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if inheritRole with a member as provider for the permissions returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, "admin").Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, "member").Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if inheritRole with an admin as provider for the permissions returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, "admin").Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with organizations as the object and owner as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "owner", "organization", mock.Anything).Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with organizations as the object and admin as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "owner", "organization", mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "admin", "organization", mock.Anything).Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with project as the object and admin as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "owner", "organization", mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "admin", "organization", mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "admin", "project", mock.Anything).Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
	t.Run("should fail if allowRole with organizations as the object and member as the role returns an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		organizationRepository := mocks.NewCoreOrganizationRepository(t)
		organizationRepository.On("Create", mock.Anything, mock.Anything).Return(nil)

		accesscontrol := mocks.NewAccesscontrolAccessControl(t)
		authSession := mocks.NewCoreAuthSession(t)
		authSession.On("GetUserID").Return("")

		core.SetSession(ctx, authSession)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)
		rbacProvider.On("GetDomainRBAC", mock.Anything).Return(accesscontrol)
		accesscontrol.On("GrantRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("InheritRole", mock.Anything, mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "owner", "organization", mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "admin", "organization", mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "admin", "project", mock.Anything).Return(nil)
		accesscontrol.On("AllowRole", "member", "organization", mock.Anything).Return(fmt.Errorf("something went wrong"))

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}

	})
}

/*func TestUpdate(t *testing.T) {
	t.Run("Should fail if the FetchMembers function throws an error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		core.SetOrganization(ctx, models.Org{Name: "TestNameLowkey"})

		organizationRepository := mocks.NewCoreOrganizationRepository(t)

		rbacProvider := mocks.NewAccesscontrolRBACProvider(t)

		projectService := mocks.NewCoreProjectService(t)
		invitationRepository := mocks.NewCoreInvitationRepository(t)

		h := org.NewHttpController(organizationRepository, rbacProvider, projectService, invitationRepository)

		err := h.Update(ctx)
		if err != nil {
			t.Fail()
		}

	})
}*/
