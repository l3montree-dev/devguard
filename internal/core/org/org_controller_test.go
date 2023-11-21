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

package org_test

import (
	"net/http/httptest"
	"testing"

	"github.com/l3montree-dev/flawfix/internal/accesscontrol"
	"github.com/l3montree-dev/flawfix/internal/core"

	"github.com/l3montree-dev/flawfix/internal/core/org"

	"github.com/l3montree-dev/flawfix/internal/testutils"
	"github.com/l3montree-dev/flawfix/mocks"
	"github.com/labstack/echo/v4"

	"github.com/stretchr/testify/assert"
)

func TestOrganizationController(t *testing.T) {
	rbacProvider := testutils.NewRBACProviderMock()
	sut := org.NewHttpController(
		&mocks.OrganizationRepository{},
		rbacProvider,
	)

	e := echo.New()
	rec := httptest.NewRecorder()

	t.Run("it it should not be possible to create an organization without a name", func(t *testing.T) {
		req := httptest.NewRequest(echo.POST, "/", testutils.ReaderFromAny(org.CreateRequest{
			Name: "",
		}))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx := e.NewContext(req, rec)

		if err := sut.Create(ctx); assert.Error(t, err) {
			assert.Equal(t, 400, err.(*echo.HTTPError).Code)
		}
	})

	t.Run("it should be possible to create an organization with a name", func(t *testing.T) {
		req := httptest.NewRequest(echo.POST, "/", testutils.ReaderFromAny(org.CreateRequest{
			Name: "test",
		}))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx := e.NewContext(req, rec)

		ctx.Set("session", testutils.NewSessionMock("test_user"))

		err := sut.Create(ctx)
		assert.NoError(t, err)
	})

	t.Run("it should bootstrap the permissions inside an organization", func(t *testing.T) {
		req := httptest.NewRequest(echo.POST, "/", testutils.ReaderFromAny(org.CreateRequest{
			Name: "test",
		}))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		ctx := e.NewContext(req, rec)

		ctx.Set("session", testutils.NewSessionMock("alice"))

		sut.Create(ctx)

		rbac := core.GetRBAC(ctx)

		// check if the permissions were created
		// the owner should be allowed to do everything
		for _, action := range []accesscontrol.Action{"read", "update", "delete"} {
			allowed, err := rbac.IsAllowed("alice", "organization", action)
			assert.NoError(t, err)
			assert.True(t, allowed, "alice should be allowed to "+action+" the organization")
		}
	})
}
