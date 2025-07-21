package accesscontrol

import (
	"errors"
	"testing"

	"github.com/l3montree-dev/devguard/internal/core"
	"github.com/l3montree-dev/devguard/internal/utils"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestIsAllowed(t *testing.T) {

	type testCase struct {
		name           string
		userID         string
		object         core.Object
		action         core.Action
		adminToken     *string
		mockRole       string
		mockRoleErr    error
		expectedResult bool
		expectErr      bool
	}

	tests := []testCase{
		{
			name:           "admin token can read",
			userID:         "admin-token",
			object:         core.ObjectProject,
			action:         core.ActionRead,
			adminToken:     utils.Ptr("admin-token"),
			expectedResult: true,
		},
		{
			name:           "all users can read organization",
			userID:         "user1",
			object:         core.ObjectOrganization,
			action:         core.ActionRead,
			adminToken:     utils.Ptr("admin-token"),
			expectedResult: true,
		},
		{
			name:           "role member can read",
			userID:         "user2",
			object:         core.ObjectProject,
			action:         core.ActionRead,
			adminToken:     utils.Ptr("admin-token"),
			mockRole:       core.RoleMember,
			expectedResult: true,
		},
		{
			name:           "role admin can update",
			userID:         "user3",
			object:         core.ObjectProject,
			action:         core.ActionUpdate,
			adminToken:     utils.Ptr("admin-token"),
			mockRole:       core.RoleAdmin,
			expectedResult: true,
		},
		{
			name:           "role member cannot update",
			userID:         "user4",
			object:         core.ObjectProject,
			action:         core.ActionUpdate,
			adminToken:     utils.Ptr("admin-token"),
			mockRole:       core.RoleMember,
			expectedResult: false,
		},
		{
			name:        "error from thirdPartyIntegration",
			userID:      "user5",
			object:      core.ObjectProject,
			action:      core.ActionRead,
			adminToken:  utils.Ptr("admin-token"),
			mockRoleErr: errors.New("some error"),
			expectErr:   true,
		},
		{
			name:           "role admin cannot delete",
			userID:         "user6",
			object:         core.ObjectProject,
			action:         core.ActionDelete,
			adminToken:     utils.Ptr("admin-token"),
			mockRole:       core.RoleAdmin,
			expectedResult: false,
		},
		{
			name:           "role member cannot delete",
			userID:         "user7",
			object:         core.ObjectProject,
			action:         core.ActionDelete,
			adminToken:     utils.Ptr("admin-token"),
			mockRole:       core.RoleMember,
			expectedResult: false,
		},
		{
			name:           "role owner can delete",
			userID:         "user8",
			object:         core.ObjectProject,
			action:         core.ActionDelete,
			adminToken:     utils.Ptr("admin-token"),
			mockRole:       core.RoleOwner,
			expectedResult: true,
		},
		{
			name:           "admin token can not create",
			userID:         "admin-token",
			object:         core.ObjectProject,
			action:         core.ActionCreate,
			adminToken:     utils.Ptr("admin-token"),
			expectedResult: false,
		},
		{
			name:           "admin token cannot delete",
			userID:         "admin-token",
			object:         core.ObjectProject,
			action:         core.ActionDelete,
			adminToken:     utils.Ptr("admin-token"),
			expectedResult: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			thirdpartyIntegrationMock := mocks.NewThirdPartyIntegration(t)
			if tc.mockRoleErr != nil || tc.mockRole != "" {
				thirdpartyIntegrationMock.
					On("GetRoleInProject",
						mock.Anything,
						tc.userID,
						mock.Anything,
						mock.Anything).
					Return(tc.mockRole, tc.mockRoleErr)
			}

			rbac := NewExternalEntityProviderRBAC(
				nil,
				thirdpartyIntegrationMock,
				"external-entity-provider-id",
				tc.adminToken,
			)

			result, err := rbac.IsAllowed(tc.userID, tc.object, tc.action)
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
	t.Run("admin token should have access", func(t *testing.T) {
		rbac := NewExternalEntityProviderRBAC(
			nil,
			nil,
			"external-entity-provider-id",
			utils.Ptr("admin-token"),
		)

		hasAccess, err := rbac.HasAccess("admin-token")
		assert.NoError(t, err)
		assert.True(t, hasAccess)
	})

	t.Run("if no admin token is provided, the third party integration should be called", func(t *testing.T) {
		thirdpartyIntegrationMock := mocks.NewThirdPartyIntegration(t)
		thirdpartyIntegrationMock.On("HasAccessToExternalEntityProvider", mock.Anything, "external-entity-provider-id").Return(true, nil)

		rbac := NewExternalEntityProviderRBAC(
			nil,
			thirdpartyIntegrationMock,
			"external-entity-provider-id",
			nil,
		)

		hasAccess, err := rbac.HasAccess("user1")
		assert.NoError(t, err)
		assert.True(t, hasAccess)
	})
	t.Run("if no admin token is provided, the third party integration should be called (false)", func(t *testing.T) {
		thirdpartyIntegrationMock := mocks.NewThirdPartyIntegration(t)
		thirdpartyIntegrationMock.On("HasAccessToExternalEntityProvider", mock.Anything, "external-entity-provider-id").Return(false, nil)

		rbac := NewExternalEntityProviderRBAC(
			nil,
			thirdpartyIntegrationMock,
			"external-entity-provider-id",
			nil,
		)

		hasAccess, err := rbac.HasAccess("user1")
		assert.NoError(t, err)
		assert.False(t, hasAccess)
	})
}
