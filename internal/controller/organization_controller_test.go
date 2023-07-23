// Copyright (C) 2023 Tim Bastin, l3montree UG (haftungsbeschränkt)
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
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package controller_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/flawfix/internal/controller"
	"github.com/l3montree-dev/flawfix/internal/dto"
	"github.com/l3montree-dev/flawfix/internal/helpers"
	"github.com/l3montree-dev/flawfix/internal/models"
	"github.com/l3montree-dev/flawfix/internal/testutils"
	"github.com/labstack/echo/v4"

	"github.com/stretchr/testify/assert"
)

func setup(req *http.Request) (*controller.OrganizationController, *echo.Echo, echo.Context) {
	rbacProvider := testutils.NewRBACProviderMock()
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	sut := controller.NewOrganizationController(testutils.NewMockRepository[uuid.UUID, models.Organization](), rbacProvider)

	e := echo.New()
	rec := httptest.NewRecorder()

	return sut, e, e.NewContext(req, rec)
}

// it should not be possible to create an organization without a name
// this should be handled by the validator
func TestCreateOrgWithoutName(t *testing.T) {
	sut, _, c := setup(httptest.NewRequest(echo.POST, "/", nil))

	if err := sut.Create(c); assert.Error(t, err) {
		assert.Equal(t, 400, err.(*echo.HTTPError).Code)
	}
}

func TestCreateOrg(t *testing.T) {
	req := dto.OrganizationCreateRequest{
		Name: "test",
	}

	sut, _, c := setup(httptest.NewRequest(echo.POST, "/", testutils.ReaderFromAny(req)))

	c.Set("session", testutils.NewSessionMock("test_user"))

	err := sut.Create(c)
	assert.NoError(t, err)
}

// it should bootstrap an organization after creation
// this includes creating the necessary permissions
func TestBootstrapOrgAfterCreation(t *testing.T) {
	req := dto.OrganizationCreateRequest{
		Name: "test",
	}

	sut, _, c := setup(httptest.NewRequest(echo.POST, "/", testutils.ReaderFromAny(req)))
	c.Set("session", testutils.NewSessionMock("alice"))

	sut.Create(c)

	rbac := helpers.GetRBAC(c)

	// check if the permissions were created
	allowed, err := rbac.IsAllowed("alice", "organization", "delete")

	assert.NoError(t, err)

	assert.True(t, allowed)
}
