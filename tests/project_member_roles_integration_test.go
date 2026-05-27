// Copyright (C) 2025 l3montree GmbH
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/labstack/echo/v4"
	"github.com/ory/client-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// ── helpers ───────────────────────────────────────────────────────────────────

// RemoveProjectMember removes a user from a project via the controller.
func (f *TestFixture) RemoveProjectMember(t testing.TB, e *echo.Echo, org models.Org, project models.Project, callerUserID string, targetUserID string) error {
	t.Helper()

	req := httptest.NewRequest("DELETE", "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("userID")
	ctx.SetParamValues(targetUserID)

	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Maybe().Return(callerUserID)
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	if err := f.App.ProjectController.RemoveMember(ctx); err != nil {
		return err
	}
	if rec.Code != 200 {
		return fmt.Errorf("RemoveProjectMember returned status %d: %s", rec.Code, rec.Body.String())
	}
	return nil
}

// ChangeProjectRole changes a user's role inside a project via the controller.
func (f *TestFixture) ChangeProjectRole(t testing.TB, e *echo.Echo, org models.Org, project models.Project, callerUserID string, targetUserID string, newRole string) error {
	t.Helper()

	body, err := json.Marshal(map[string]string{"role": newRole})
	require.NoError(t, err)

	req := httptest.NewRequest("PATCH", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)
	ctx.SetParamNames("userID")
	ctx.SetParamValues(targetUserID)

	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Return(callerUserID)
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	if err := f.App.ProjectController.ChangeRole(ctx); err != nil {
		return err
	}
	if rec.Code != 200 {
		return fmt.Errorf("ChangeProjectRole returned status %d: %s", rec.Code, rec.Body.String())
	}
	return nil
}

// CreateProject creates a project via the controller inside the given org.
// Pass a non-nil parentID to create a subproject.
func (f *TestFixture) CreateProjectViaController(t testing.TB, e *echo.Echo, org models.Org, callerUserID string, name string, parentID *uuid.UUID) models.Project {
	t.Helper()

	body, err := json.Marshal(dtos.ProjectCreateRequest{Name: name, ParentID: parentID})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Maybe().Return(callerUserID)
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, org)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	require.NoError(t, f.App.ProjectController.Create(ctx))
	require.Equal(t, 200, rec.Code)

	var project models.Project
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &project))
	return project
}

// InviteToProject grants a user membership in a project via the InviteMembers endpoint.
// The user must already be a member of the org.
func (f *TestFixture) InviteToProject(t testing.TB, e *echo.Echo, org models.Org, project models.Project, callerUserID string, targetUserID string) {
	t.Helper()

	body, err := json.Marshal(dtos.ProjectInviteRequest{Ids: []string{targetUserID}})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Maybe().Return(callerUserID)
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	require.NoError(t, f.App.ProjectController.InviteMembers(ctx))
	require.Equal(t, 200, rec.Code)
}

// GetProjectMembers calls the project Members endpoint and returns the member list.
// identities is a lookup map used to resolve user IDs that RBAC reports as members.
func (f *TestFixture) GetProjectMembers(t testing.TB, e *echo.Echo, org models.Org, project models.Project, identities []client.Identity) []dtos.UserDTO {
	t.Helper()

	byID := make(map[string]client.Identity, len(identities))
	for _, id := range identities {
		byID[id.Id] = id
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	// Pre-resolve which identities RBAC considers members, so the mock returns
	// only those — not every identity in the lookup map.
	rbacMembers, err := f.App.RBACProvider.GetDomainRBAC(org.ID.String()).GetAllMembersOfProject(project.ID.String())
	require.NoError(t, err)
	var filteredIdentities []client.Identity
	for _, memberID := range rbacMembers {
		if identity, ok := byID[memberID]; ok {
			filteredIdentities = append(filteredIdentities, identity)
		}
	}

	adminClient := mocks.NewAdminClient(t)
	adminClient.On("ListUser", mock.Anything).Return(filteredIdentities, nil)
	shared.SetAuthAdminClient(ctx, adminClient)

	require.NoError(t, f.App.ProjectController.Members(ctx))
	require.Equal(t, 200, rec.Code)

	var members []dtos.UserDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &members))
	return members
}

// CreateAsset creates an asset via the controller inside the given project.
func (f *TestFixture) CreateAssetViaController(t testing.TB, e *echo.Echo, org models.Org, project models.Project, callerUserID string, name string) models.Asset {
	t.Helper()

	body, err := json.Marshal(dtos.AssetCreateRequest{
		Name:                       name,
		ConfidentialityRequirement: "low",
		IntegrityRequirement:       "low",
		AvailabilityRequirement:    "low",
	})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Return(callerUserID)
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	require.NoError(t, f.App.AssetController.Create(ctx))
	require.Equal(t, 200, rec.Code)

	var assetDTO dtos.AssetDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &assetDTO))

	// resolve to full model for later use
	asset, err := f.App.AssetRepository.Read(req.Context(), nil, assetDTO.ID)
	require.NoError(t, err)
	return asset
}

// InviteToAsset grants a user membership in an asset via the InviteMembers endpoint.
// The user must already be a member of the project.
func (f *TestFixture) InviteToAsset(t testing.TB, e *echo.Echo, org models.Org, project models.Project, asset models.Asset, callerUserID string, targetUserID string) {
	t.Helper()

	body, err := json.Marshal(dtos.AssetInviteToAssetRequest{Ids: []string{targetUserID}})
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	session := mocks.NewAuthSession(t)
	session.On("GetUserID").Return(callerUserID)
	shared.SetSession(ctx, session)
	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetAsset(ctx, asset)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	require.NoError(t, f.App.AssetController.InviteMembers(ctx))
	require.Equal(t, 200, rec.Code)
}

// GetAssetMembers calls the asset Members endpoint and returns the member list.
// identities is a lookup map used to resolve user IDs that RBAC reports as members.
func (f *TestFixture) GetAssetMembers(t testing.TB, e *echo.Echo, org models.Org, project models.Project, asset models.Asset, identities []client.Identity) []dtos.UserDTO {
	t.Helper()

	byID := make(map[string]client.Identity, len(identities))
	for _, id := range identities {
		byID[id.Id] = id
	}

	rbacMembers, err := f.App.RBACProvider.GetDomainRBAC(org.ID.String()).GetAllMembersOfAsset(asset.ID.String())
	require.NoError(t, err)
	var filteredIdentities []client.Identity
	for _, memberID := range rbacMembers {
		if identity, ok := byID[memberID]; ok {
			filteredIdentities = append(filteredIdentities, identity)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()
	ctx := e.NewContext(req, rec)

	shared.SetOrg(ctx, org)
	shared.SetProject(ctx, project)
	shared.SetAsset(ctx, asset)
	shared.SetRBAC(ctx, f.App.RBACProvider.GetDomainRBAC(org.ID.String()))

	adminClient := mocks.NewAdminClient(t)
	adminClient.On("ListUser", mock.Anything).Return(filteredIdentities, nil)
	shared.SetAuthAdminClient(ctx, adminClient)

	require.NoError(t, f.App.AssetController.Members(ctx))
	require.Equal(t, 200, rec.Code)

	var members []dtos.UserDTO
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &members))
	return members
}

// ── test ─────────────────────────────────────────────────────────────────────

// TestMemberRolesAcrossProjectHierarchy verifies that a user who is only an org
// member (not explicitly invited to project/subproject/asset) has no role at
// those lower levels.
func TestMemberRolesAcrossProjectHierarchy(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		const (
			userAID    = "user-a-id"
			userBID    = "user-b-id"
			userBEmail = "user-b@example.com"
		)

		e := echo.New()

		// Setup: User A creates an org, invites User B who accepts.
		// User B is NOT invited to any project, subproject or asset.
		org := f.CreateOrgWithOwner(t, e, userAID, "test-hierarchy-org")
		f.AcceptInvitation(t, e, f.InviteMember(t, e, org, userAID, userBEmail).Code, userBID, userBEmail)

		// Create project → subproject → asset (no invites for User B)
		project := f.CreateProjectViaController(t, e, org, userAID, "test-project", nil)
		subproject := f.CreateProjectViaController(t, e, org, userAID, "test-subproject", &project.ID)
		asset := f.CreateAssetViaController(t, e, org, subproject, userAID, "test-asset")

		// User A is a project member via org-admin → project-admin → project-member inheritance.
		// User B is only an org member and was never invited to any project or asset,
		// so User B must not appear in the project/subproject/asset member lists.
		allIdentities := []client.Identity{
			{Id: userAID, Traits: map[string]any{"email": "user-a@example.com", "name": "User A"}},
			{Id: userBID, Traits: map[string]any{"email": userBEmail, "name": "User B"}},
		}

		memberIDs := func(members []dtos.UserDTO) map[string]struct{} {
			m := make(map[string]struct{}, len(members))
			for _, u := range members {
				m[u.ID] = struct{}{}
			}
			return m
		}

		t.Run("user B is member of org", func(t *testing.T) {
			ids := memberIDs(f.GetOrgMembers(t, e, org, allIdentities))
			assert.Contains(t, ids, userBID, "user B should appear as org member")
		})

		t.Run("user B has no role in project without invite", func(t *testing.T) {
			ids := memberIDs(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.NotContains(t, ids, userBID, "user B should not appear as project member without explicit invite")
		})

		t.Run("user B has no role in subproject without invite", func(t *testing.T) {
			ids := memberIDs(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.NotContains(t, ids, userBID, "user B should not appear as subproject member without explicit invite")
		})

		t.Run("user B has no role in asset without invite", func(t *testing.T) {
			ids := memberIDs(f.GetAssetMembers(t, e, org, subproject, asset, allIdentities))
			assert.NotContains(t, ids, userBID, "user B should not appear as asset member without explicit invite")
		})
	})
}

// TestOrgAdminRolePropagatesDownHierarchy verifies that promoting a user to org admin
// automatically gives them admin access at the project, subproject and asset level
// through role inheritance (org admin → project admin → asset admin).
func TestOrgAdminRolePropagatesDownHierarchy(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		const (
			userAID    = "user-a-id"
			userBID    = "user-b-id"
			userBEmail = "user-b@example.com"
		)

		e := echo.New()

		// Setup: org, project → subproject → asset, User B as org member
		org := f.CreateOrgWithOwner(t, e, userAID, "test-admin-propagation")
		f.AcceptInvitation(t, e, f.InviteMember(t, e, org, userAID, userBEmail).Code, userBID, userBEmail)

		project := f.CreateProjectViaController(t, e, org, userAID, "test-project", nil)
		subproject := f.CreateProjectViaController(t, e, org, userAID, "test-subproject", &project.ID)
		asset := f.CreateAssetViaController(t, e, org, subproject, userAID, "test-asset")

		// User A promotes User B to org admin
		require.NoError(t, f.ChangeRole(t, e, org, userAID, userBID, "admin"))

		allIdentities := []client.Identity{
			{Id: userAID, Traits: map[string]any{"email": "user-a@example.com", "name": "User A"}},
			{Id: userBID, Traits: map[string]any{"email": userBEmail, "name": "User B"}},
		}

		t.Run("user B is admin of org", func(t *testing.T) {
			roles := rolesFromMembers(f.GetOrgMembers(t, e, org, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has role admin in project", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})
		t.Run("user B has role admin in subproject", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has role admin in asset", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, subproject, asset, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		// Demote User B back to member and observe what role they have at each level
		require.NoError(t, f.ChangeRole(t, e, org, userAID, userBID, "member"))

		t.Run("user B is member of org after demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetOrgMembers(t, e, org, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in project after demotion to org member", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in subproject after demotion to org member", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after demotion to org member", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, subproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

	})
}

// TestProjectInvitePropagatesDownHierarchy verifies that inviting an org member to a
// project gives them access in that project. It also logs what role they get in
// a subproject and asset that they were not explicitly invited to.
func TestProjectInvitePropagatesDownHierarchy(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		const (
			userAID    = "user-a-id"
			userBID    = "user-b-id"
			userBEmail = "user-b@example.com"
		)

		e := echo.New()

		org := f.CreateOrgWithOwner(t, e, userAID, "test-project-invite-propagation")
		f.AcceptInvitation(t, e, f.InviteMember(t, e, org, userAID, userBEmail).Code, userBID, userBEmail)

		// Hierarchy: project → subproject → child subproject → asset
		project := f.CreateProjectViaController(t, e, org, userAID, "test-project", nil)
		subproject := f.CreateProjectViaController(t, e, org, userAID, "test-subproject", &project.ID)
		childSubproject := f.CreateProjectViaController(t, e, org, userAID, "test-child-subproject", &subproject.ID)
		asset := f.CreateAssetViaController(t, e, org, childSubproject, userAID, "test-asset")

		allIdentities := []client.Identity{
			{Id: userAID, Traits: map[string]any{"email": "user-a@example.com", "name": "User A"}},
			{Id: userBID, Traits: map[string]any{"email": userBEmail, "name": "User B"}},
		}

		// User B is only an org member — no role expected anywhere below org level
		t.Run("user B has no role in project before invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in subproject before invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in child subproject before invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset before invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// Invite User B to the top-level project
		f.InviteToProject(t, e, org, project, userAID, userBID)

		t.Run("user B has member role in project after invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in subproject after project invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in child subproject after project invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after project invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// Promote User B to admin in the top-level project
		require.NoError(t, f.ChangeProjectRole(t, e, org, project, userAID, userBID, "admin"))

		t.Run("user B has admin role in project after promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B role in subproject after project admin promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B role in child subproject after project admin promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B role in asset after project admin promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		// Demote User B back to member in the top-level project
		require.NoError(t, f.ChangeProjectRole(t, e, org, project, userAID, userBID, "member"))

		t.Run("user B has member role in project after demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in subproject after project demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in child subproject after project demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after project demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// Invite User B directly to the subproject
		f.InviteToProject(t, e, org, subproject, userAID, userBID)

		t.Run("user B has member role in subproject after subproject invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in child subproject after subproject invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after subproject invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// Promote User B to admin in subproject
		require.NoError(t, f.ChangeProjectRole(t, e, org, subproject, userAID, userBID, "admin"))

		t.Run("user B has admin role in subproject after promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has admin role in child subproject after subproject admin promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has admin role in asset after subproject admin promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		// Demote User B back to member in subproject
		require.NoError(t, f.ChangeProjectRole(t, e, org, subproject, userAID, userBID, "member"))

		t.Run("user B has member role in subproject after demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in child subproject after subproject demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after subproject demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// Invite User B directly to the child subproject
		f.InviteToProject(t, e, org, childSubproject, userAID, userBID)

		t.Run("user B has member role in child subproject after child subproject invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in asset after child subproject invite", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// Promote User B to admin in child subproject
		require.NoError(t, f.ChangeProjectRole(t, e, org, childSubproject, userAID, userBID, "admin"))

		t.Run("user B has admin role in child subproject after promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has admin role in asset after child subproject admin promotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		// Demote User B back to member in child subproject
		require.NoError(t, f.ChangeProjectRole(t, e, org, childSubproject, userAID, userBID, "member"))

		t.Run("user B has member role in child subproject after demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, string(shared.RoleMember), roles[userBID])
		})

		t.Run("user B has no role in asset after child subproject demotion", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})
	})
}

// TestProjectRemovalClearsHierarchyRoles mirrors TestProjectInvitePropagatesDownHierarchy
// but instead of changing roles it removes the user from each level and checks that
// roles at lower levels become empty.
func TestProjectRemovalClearsHierarchyRoles(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		const (
			userAID    = "user-a-id"
			userBID    = "user-b-id"
			userBEmail = "user-b@example.com"
		)

		e := echo.New()

		org := f.CreateOrgWithOwner(t, e, userAID, "test-project-removal")
		f.AcceptInvitation(t, e, f.InviteMember(t, e, org, userAID, userBEmail).Code, userBID, userBEmail)

		// Hierarchy: project → subproject → child subproject → asset
		project := f.CreateProjectViaController(t, e, org, userAID, "test-project", nil)
		subproject := f.CreateProjectViaController(t, e, org, userAID, "test-subproject", &project.ID)
		childSubproject := f.CreateProjectViaController(t, e, org, userAID, "test-child-subproject", &subproject.ID)
		asset := f.CreateAssetViaController(t, e, org, childSubproject, userAID, "test-asset")

		allIdentities := []client.Identity{
			{Id: userAID, Traits: map[string]any{"email": "user-a@example.com", "name": "User A"}},
			{Id: userBID, Traits: map[string]any{"email": userBEmail, "name": "User B"}},
		}

		// ── invite to project, promote to admin, then remove from project ────────

		f.InviteToProject(t, e, org, project, userAID, userBID)
		require.NoError(t, f.ChangeProjectRole(t, e, org, project, userAID, userBID, "admin"))

		t.Run("user B is admin in project before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		require.NoError(t, f.RemoveProjectMember(t, e, org, project, userAID, userBID))

		t.Run("user B has no role in project after project removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in subproject after project removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in child subproject after project removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after project removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// ── invite to subproject, promote to admin, then remove from subproject ──

		f.InviteToProject(t, e, org, subproject, userAID, userBID)
		require.NoError(t, f.ChangeProjectRole(t, e, org, subproject, userAID, userBID, "admin"))

		t.Run("user B is admin in subproject before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		require.NoError(t, f.RemoveProjectMember(t, e, org, subproject, userAID, userBID))

		t.Run("user B has no role in subproject after subproject removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in child subproject after subproject removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after subproject removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		// ── invite to child subproject, promote to admin, then remove ────────────

		f.InviteToProject(t, e, org, childSubproject, userAID, userBID)
		require.NoError(t, f.ChangeProjectRole(t, e, org, childSubproject, userAID, userBID, "admin"))

		t.Run("user B is admin in child subproject before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		require.NoError(t, f.RemoveProjectMember(t, e, org, childSubproject, userAID, userBID))

		t.Run("user B has no role in child subproject after child subproject removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, childSubproject, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})

		t.Run("user B has no role in asset after child subproject removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, childSubproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID])
		})
	})
}

// TestOrgMemberRemovedFromOrgClearsHierarchyRoles verifies that removing a user from
// an org (who was previously promoted to admin) removes their access at project,
// subproject and asset level as well.
func TestOrgMemberRemovedFromOrgClearsHierarchyRoles(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		const (
			userAID    = "user-a-id"
			userBID    = "user-b-id"
			userBEmail = "user-b@example.com"
		)

		e := echo.New()

		// Setup: org, project → subproject → asset, User B as org member promoted to admin
		org := f.CreateOrgWithOwner(t, e, userAID, "test-admin-removed")
		f.AcceptInvitation(t, e, f.InviteMember(t, e, org, userAID, userBEmail).Code, userBID, userBEmail)

		project := f.CreateProjectViaController(t, e, org, userAID, "test-project", nil)
		subproject := f.CreateProjectViaController(t, e, org, userAID, "test-subproject", &project.ID)
		asset := f.CreateAssetViaController(t, e, org, subproject, userAID, "test-asset")

		// User A promotes User B to org admin
		require.NoError(t, f.ChangeRole(t, e, org, userAID, userBID, "admin"))

		allIdentities := []client.Identity{
			{Id: userAID, Traits: map[string]any{"email": "user-a@example.com", "name": "User A"}},
			{Id: userBID, Traits: map[string]any{"email": userBEmail, "name": "User B"}},
		}

		t.Run("user B is admin of org before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetOrgMembers(t, e, org, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has role admin in project before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has role admin in subproject before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		t.Run("user B has role admin in asset before removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, subproject, asset, allIdentities))
			assert.Equal(t, string(shared.RoleAdmin), roles[userBID])
		})

		// Remove User B from the org entirely
		require.NoError(t, f.RemoveMember(t, e, org, userAID, userBID))

		t.Run("user B is no longer in org after removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetOrgMembers(t, e, org, allIdentities))
			_, exists := roles[userBID]
			assert.False(t, exists, "user B should not appear in org members after removal")
		})

		t.Run("user B role in project after org removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, project, allIdentities))
			assert.Equal(t, "", roles[userBID], "user B should have no role in project after org removal")
		})

		t.Run("user B role in subproject after org removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetProjectMembers(t, e, org, subproject, allIdentities))
			assert.Equal(t, "", roles[userBID], "user B should have no role in subproject after org removal")
		})

		t.Run("user B role in asset after org removal", func(t *testing.T) {
			roles := rolesFromMembers(f.GetAssetMembers(t, e, org, subproject, asset, allIdentities))
			assert.Equal(t, "", roles[userBID], "user B should have no role in asset after org removal")
		})
	})
}
