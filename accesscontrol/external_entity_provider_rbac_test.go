package accesscontrol

import (
	"errors"
	"testing"

	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
)

func TestIsAllowed(t *testing.T) {

	type testCase struct {
		name           string
		userID         string
		object         shared.Object
		action         shared.Action
		mockResult     bool
		mockErr        error
		expectedResult bool
		expectErr      bool
	}

	tests := []testCase{
		{
			name:           "all users can read organization",
			userID:         "user1",
			object:         shared.ObjectOrganization,
			action:         shared.ActionRead,
			expectedResult: true,
		},

		{
			name:      "error from rootAccessControl",
			userID:    "user5",
			object:    shared.ObjectProject,
			action:    shared.ActionRead,
			mockErr:   errors.New("some error"),
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := mocks.NewContext(t)
			rootAccessControl := mocks.NewAccessControl(t)
			thirdpartyIntegrationMock := mocks.NewIntegrationAggregate(t)

			// Only mock rootAccessControl if we expect it to be called
			if tc.userID != "admin-token" && tc.object != shared.ObjectOrganization {
				rootAccessControl.On("IsAllowed", NewSession(tc.userID, nil, false), tc.object, tc.action).Return(tc.mockResult, tc.mockErr)
			}

			rbac := NewExternalEntityProviderRBAC(
				ctx,
				rootAccessControl,
				thirdpartyIntegrationMock,
				"external-entity-provider-id",
			)

			result, err := rbac.IsAllowed(NewSession(tc.userID, nil, false), tc.object, tc.action)
			if tc.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedResult, result)
			}
		})
	}
}

func TestHasAccess(t *testing.T) {

	t.Run("the third party integration should be called", func(t *testing.T) {
		ctx := mocks.NewContext(t)
		rootAccessControl := mocks.NewAccessControl(t)
		thirdpartyIntegrationMock := mocks.NewIntegrationAggregate(t)
		thirdpartyIntegrationMock.On("HasAccessToExternalEntityProvider", ctx, "external-entity-provider-id").Return(true, nil)

		rbac := NewExternalEntityProviderRBAC(
			ctx,
			rootAccessControl,
			thirdpartyIntegrationMock,
			"external-entity-provider-id",
		)

		hasAccess, err := rbac.HasAccess(NewSession("userID", nil, false))
		assert.NoError(t, err)
		assert.True(t, hasAccess)
	})

	t.Run("if no admin token is provided, the third party integration should be called (false)", func(t *testing.T) {
		ctx := mocks.NewContext(t)
		rootAccessControl := mocks.NewAccessControl(t)
		thirdpartyIntegrationMock := mocks.NewIntegrationAggregate(t)
		thirdpartyIntegrationMock.On("HasAccessToExternalEntityProvider", ctx, "external-entity-provider-id").Return(false, nil)

		rbac := NewExternalEntityProviderRBAC(
			ctx,
			rootAccessControl,
			thirdpartyIntegrationMock,
			"external-entity-provider-id",
		)

		hasAccess, err := rbac.HasAccess(NewSession("userID", nil, false))
		assert.NoError(t, err)
		assert.False(t, hasAccess)
	})
}
