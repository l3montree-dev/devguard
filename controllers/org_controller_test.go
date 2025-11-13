package controllers

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core/org"
	"github.com/l3montree-dev/devguard/internal/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/stretchr/testify/mock"
)

// Test function for Create and bootstrap from org_controller
func TestCreate(t *testing.T) {
	t.Run("Should fail if a context with wrong parameters is provided", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", bytes.NewBufferString("fantasy"))

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		h := org.NewHTTPController(nil, nil, nil, nil, nil)

		err := h.Create(ctx)
		if err == nil {
			t.Fail()
		}
	})
	t.Run("Should fail if the context is in the wrong format", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/webhook", nil)

		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{Name: "fantasy", Slug: "fantasy"})

		h := org.NewHTTPController(nil, nil, nil, nil, nil)

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

		h := org.NewHTTPController(nil, nil, nil, nil, nil)

		err := h.Create(ctx)
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

		_, err := org.FetchMembersOfOrganization(ctx)
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

		_, err := org.FetchMembersOfOrganization(ctx)
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
		thirdPartyIntegration.On("GetUsers", mock.Anything).Return([]dtos.User{})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{})
		shared.SetRBAC(ctx, accesscontrol)
		shared.SetAuthAdminClient(ctx, adminClient)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		_, err := org.FetchMembersOfOrganization(ctx)
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
		thirdPartyIntegration.On("GetUsers", mock.Anything).Return([]dtos.User{})

		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name": "cool org"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		e := echo.New()
		ctx := e.NewContext(req, httptest.NewRecorder())

		shared.SetOrg(ctx, models.Org{})
		shared.SetRBAC(ctx, accesscontrol)
		shared.SetAuthAdminClient(ctx, adminClient)
		shared.SetThirdPartyIntegration(ctx, thirdPartyIntegration)

		_, err := org.FetchMembersOfOrganization(ctx)
		if err != nil {

			t.Fail()
		}
	})
}
