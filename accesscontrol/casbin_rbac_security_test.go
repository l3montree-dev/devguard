// Copyright (C) 2026 l3montree GmbH
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

package accesscontrol

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/mocks"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

type securityFixture struct {
	orgA, orgB                   uuid.UUID
	projA1, projA2, projB1       models.Project
	assetA1a, assetA1b, assetA2a models.Asset
	assetB1a                     models.Asset
	rbacOrgA                     *casbinRBAC
}

func newSecurityFixture(t *testing.T) *securityFixture {
	t.Helper()

	f := &securityFixture{orgA: uuid.New(), orgB: uuid.New()}

	f.projA1 = models.Project{Model: models.Model{ID: uuid.New()}, OrganizationID: f.orgA, Slug: "proj-a1"}
	f.projA2 = models.Project{Model: models.Model{ID: uuid.New()}, OrganizationID: f.orgA, Slug: "proj-a2"}
	f.projB1 = models.Project{Model: models.Model{ID: uuid.New()}, OrganizationID: f.orgB, Slug: "proj-b1"}

	f.assetA1a = models.Asset{Model: models.Model{ID: uuid.New()}, ProjectID: f.projA1.ID, Project: f.projA1, Slug: "asset-a1a"}
	f.assetA1b = models.Asset{Model: models.Model{ID: uuid.New()}, ProjectID: f.projA1.ID, Project: f.projA1, Slug: "asset-a1b"}
	f.assetA2a = models.Asset{Model: models.Model{ID: uuid.New()}, ProjectID: f.projA2.ID, Project: f.projA2, Slug: "asset-a2a"}
	f.assetB1a = models.Asset{Model: models.Model{ID: uuid.New()}, ProjectID: f.projB1.ID, Project: f.projB1, Slug: "asset-b1a"}

	projectRepo := mocks.NewProjectRepository(t)
	assetRepo := mocks.NewAssetRepository(t)

	for _, p := range []models.Project{f.projA1, f.projA2, f.projB1} {
		projectRepo.EXPECT().Read(mockAnythingCtx, (*gorm.DB)(nil), p.ID).Return(p, nil).Maybe()
	}
	projectRepo.EXPECT().GetByOrgID(mockAnythingCtx, (*gorm.DB)(nil), f.orgA).
		Return([]models.Project{f.projA1, f.projA2}, nil).Maybe()

	for _, a := range []models.Asset{f.assetA1a, f.assetA1b, f.assetA2a, f.assetB1a} {
		assetRepo.EXPECT().ReadWithProject(mockAnythingCtx, (*gorm.DB)(nil), a.ID).Return(a, nil).Maybe()
	}
	assetRepo.EXPECT().GetByOrgID(mockAnythingCtx, (*gorm.DB)(nil), f.orgA).
		Return([]models.Asset{f.assetA1a, f.assetA1b, f.assetA2a}, nil).Maybe()
	assetRepo.EXPECT().GetByProjectID(mockAnythingCtx, (*gorm.DB)(nil), f.projA1.ID).
		Return([]models.Asset{f.assetA1a, f.assetA1b}, nil).Maybe()

	f.rbacOrgA = &casbinRBAC{domain: f.orgA.String(), enforcer: newTestEnforcer(t), projectRepository: projectRepo, assetRepository: assetRepo}

	return f
}

var mockAnythingCtx = context.Background()

func orgSession(orgID uuid.UUID) shared.AuthSession {
	return shared.NewSession(orgID.String(), shared.SessionActorOrg, nil, false)
}

func projectSession(projectID uuid.UUID) shared.AuthSession {
	return shared.NewSession(projectID.String(), shared.SessionActorProject, nil, false)
}

func assetSession(assetID uuid.UUID) shared.AuthSession {
	return shared.NewSession(assetID.String(), shared.SessionActorAsset, nil, false)
}

func TestSecurityOrgTokenCannotActOnForeignOrgProject(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := orgSession(f.orgA)

	allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projA1, session, shared.ObjectProject, shared.ActionRead)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, action := range []shared.Action{shared.ActionRead, shared.ActionCreate, shared.ActionUpdate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projB1, session, shared.ObjectProject, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on foreign org's project", action)
	}
}

func TestSecurityOrgTokenCannotActOnForeignOrgAsset(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := orgSession(f.orgA)

	allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetA1a, session, shared.ObjectAsset, shared.ActionRead)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, action := range []shared.Action{shared.ActionRead, shared.ActionCreate, shared.ActionUpdate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetB1a, session, shared.ObjectAsset, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on foreign org's asset", action)
	}
}

func TestSecurityOrgTokenCannotDeleteOrUpdateItsOwnOrganization(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := orgSession(f.orgA)

	allowed, err := f.rbacOrgA.IsAllowed(ctx, session, shared.ObjectOrganization, shared.ActionRead)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, action := range []shared.Action{shared.ActionUpdate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowed(ctx, session, shared.ObjectOrganization, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on own organization", action)
	}
}

func TestSecurityOrgTokenProjectAndAssetListsDoNotLeakForeignOrg(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := orgSession(f.orgA)

	projects, err := f.rbacOrgA.GetAllProjectsForSession(ctx, session)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{f.projA1.ID.String(), f.projA2.ID.String()}, projects)

	assets, err := f.rbacOrgA.GetAllAssetsForSession(ctx, session)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{f.assetA1a.ID.String(), f.assetA1b.ID.String(), f.assetA2a.ID.String()}, assets)
}

func TestSecurityProjectTokenCannotActOnSiblingProject(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := projectSession(f.projA1.ID)

	allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projA1, session, shared.ObjectAsset, shared.ActionCreate)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, action := range []shared.Action{shared.ActionRead, shared.ActionCreate, shared.ActionUpdate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projA2, session, shared.ObjectAsset, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on sibling project", action)
	}
}

func TestSecurityProjectTokenCannotActOnForeignOrgProject(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := projectSession(f.projA1.ID)

	allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projB1, session, shared.ObjectAsset, shared.ActionRead)
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestSecurityProjectTokenCannotDeleteOrUpdateItsOwnProject(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := projectSession(f.projA1.ID)

	for _, action := range []shared.Action{shared.ActionUpdate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projA1, session, shared.ObjectProject, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on own project", action)
	}
}

func TestSecurityProjectTokenCannotActOnAssetOfSiblingProject(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := projectSession(f.projA1.ID)

	allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetA1a, session, shared.ObjectAsset, shared.ActionDelete)
	require.NoError(t, err)
	assert.True(t, allowed)

	allowed, err = f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetA2a, session, shared.ObjectAsset, shared.ActionRead)
	require.NoError(t, err)
	assert.False(t, allowed)

	allowed, err = f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetB1a, session, shared.ObjectAsset, shared.ActionRead)
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestSecurityProjectTokenAssetListDoesNotLeakSiblingProject(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := projectSession(f.projA1.ID)

	assets, err := f.rbacOrgA.GetAllAssetsForSession(ctx, session)
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{f.assetA1a.ID.String(), f.assetA1b.ID.String()}, assets)

	projects, err := f.rbacOrgA.GetAllProjectsForSession(ctx, session)
	require.NoError(t, err)
	assert.Equal(t, []string{f.projA1.ID.String()}, projects)
}

func TestSecurityAssetTokenCannotActOnSiblingAsset(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := assetSession(f.assetA1a.ID)

	allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetA1a, session, shared.ObjectAsset, shared.ActionRead)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, sibling := range []models.Asset{f.assetA1b, f.assetA2a, f.assetB1a} {
		allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &sibling, session, shared.ObjectAsset, shared.ActionRead)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "sibling asset %s", sibling.Slug)
	}
}

func TestSecurityAssetTokenCannotActOnItsOwnProjectOrOrganization(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := assetSession(f.assetA1a.ID)

	allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projA1, session, shared.ObjectProject, shared.ActionRead)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, action := range []shared.Action{shared.ActionCreate, shared.ActionUpdate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowedInProject(ctx, &f.projA1, session, shared.ObjectProject, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on own project", action)
	}

	allowed, err = f.rbacOrgA.IsAllowed(ctx, session, shared.ObjectOrganization, shared.ActionRead)
	require.NoError(t, err)
	assert.True(t, allowed)
	allowed, err = f.rbacOrgA.IsAllowed(ctx, session, shared.ObjectOrganization, shared.ActionDelete)
	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestSecurityAssetTokenCannotDeleteOrCreateItself(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := assetSession(f.assetA1a.ID)

	allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetA1a, session, shared.ObjectAsset, shared.ActionUpdate)
	require.NoError(t, err)
	assert.True(t, allowed)

	for _, action := range []shared.Action{shared.ActionCreate, shared.ActionDelete} {
		allowed, err := f.rbacOrgA.IsAllowedInAsset(ctx, &f.assetA1a, session, shared.ObjectAsset, action)
		require.NoError(t, err)
		assert.Falsef(t, allowed, "action %q on itself", action)
	}
}

func TestSecurityAssetTokenHasNoProjectsOrOtherAssets(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()
	session := assetSession(f.assetA1a.ID)

	projects, err := f.rbacOrgA.GetAllProjectsForSession(ctx, session)
	require.NoError(t, err)
	assert.Empty(t, projects)

	assets, err := f.rbacOrgA.GetAllAssetsForSession(ctx, session)
	require.NoError(t, err)
	assert.Equal(t, []string{f.assetA1a.ID.String()}, assets)
}

// A malformed actor id (or a scope-confusion bug feeding a user id into a
// project/asset branch) must fail closed: an error, never a silent grant.
func TestSecurityMalformedActorIDDoesNotPanicOrGrantAccess(t *testing.T) {
	f := newSecurityFixture(t)
	ctx := context.Background()

	for _, actorType := range []shared.SessionActor{shared.SessionActorProject, shared.SessionActorAsset} {
		session := shared.NewSession("not-a-uuid", actorType, nil, false)

		allowed, err := f.rbacOrgA.HasAccess(ctx, session)
		assert.Error(t, err)
		assert.False(t, allowed)

		allowed, err = f.rbacOrgA.IsAllowed(ctx, session, shared.ObjectAsset, shared.ActionRead)
		assert.Error(t, err)
		assert.False(t, allowed)
	}
}
