// Copyright 2025 l3montree GmbH.
// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"context"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createProviderProjectAndAsset creates a project and an asset managed by the given provider
// and bootstraps them like production does, so the org admin inherits project and asset admin
func createProviderProjectAndAsset(t *testing.T, f *TestFixture, rbac shared.AccessControl, org models.Org, providerID, name string) (models.Project, models.Asset) {
	t.Helper()
	ctx := context.Background()

	project := models.Project{
		Name:                     name,
		Slug:                     name,
		OrganizationID:           org.ID,
		ExternalEntityProviderID: &providerID,
		ExternalEntityID:         &name,
	}
	require.NoError(t, f.DB.Create(&project).Error)
	require.NoError(t, f.App.ProjectService.BootstrapProject(ctx, rbac, &project))

	assetName := name + "-asset"
	asset := models.Asset{
		Name:                     assetName,
		Slug:                     assetName,
		ProjectID:                project.ID,
		ExternalEntityProviderID: &providerID,
		ExternalEntityID:         &assetName,
	}
	require.NoError(t, f.DB.Create(&asset).Error)
	require.NoError(t, f.App.AssetService.BootstrapAsset(ctx, rbac, &asset))

	return project, asset
}

func projectExists(t *testing.T, f *TestFixture, project models.Project) bool {
	t.Helper()
	var count int64
	require.NoError(t, f.DB.Model(&models.Project{}).Where("id = ?", project.ID).Count(&count).Error)
	return count > 0
}

func assetExists(t *testing.T, f *TestFixture, asset models.Asset) bool {
	t.Helper()
	var count int64
	require.NoError(t, f.DB.Model(&models.Asset{}).Where("id = ?", asset.ID).Count(&count).Error)
	return count > 0
}

func TestExternalEntityProviderCollectGarbage(t *testing.T) {
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		ctx := context.Background()

		t.Run("should not delete projects and assets of a content provider (e.g. k8s image inventory) in a regular org with only an org owner", func(t *testing.T) {
			org := f.CreateOrg("regular-org")
			rbac := f.App.RBACProvider.GetDomainRBAC(org.ID.String())
			require.NoError(t, shared.BootstrapOrg(ctx, rbac, "owner-user", shared.RoleOwner))

			project, asset := createProviderProjectAndAsset(t, f, rbac, org, "ext:k8s-image-inventory", "kube-system")

			require.NoError(t, f.App.ExternalEntityProviderService.CollectGarbage(ctx))

			assert.True(t, projectExists(t, f, project))
			assert.True(t, assetExists(t, f, asset))
		})

		t.Run("should delete projects and assets of a gitlab provider org which no user can reach anymore", func(t *testing.T) {
			providerID := "gitlab"
			org := models.Org{Name: providerID, Slug: "@" + providerID, ExternalEntityProviderID: &providerID}
			require.NoError(t, f.DB.Create(&org).Error)
			rbac := f.App.RBACProvider.GetDomainRBAC(org.ID.String())
			// an org owner must not keep provider projects alive
			require.NoError(t, shared.BootstrapOrg(ctx, rbac, "gitlab-org-owner", shared.RoleOwner))

			project, asset := createProviderProjectAndAsset(t, f, rbac, org, "gitlab", "removed-group")

			require.NoError(t, f.App.ExternalEntityProviderService.CollectGarbage(ctx))

			assert.False(t, projectExists(t, f, project))
			assert.False(t, assetExists(t, f, asset))
		})

		t.Run("should keep projects and assets of a gitlab provider org which a user can still reach", func(t *testing.T) {
			providerID := "opencode"
			org := models.Org{Name: providerID, Slug: "@" + providerID, ExternalEntityProviderID: &providerID}
			require.NoError(t, f.DB.Create(&org).Error)
			rbac := f.App.RBACProvider.GetDomainRBAC(org.ID.String())

			project, asset := createProviderProjectAndAsset(t, f, rbac, org, "opencode", "synced-group")

			// the sync grants the roles of the user directly on the project and the asset
			session := shared.NewSession("synced-user", shared.SessionActorUser, nil, false)
			require.NoError(t, rbac.GrantRoleInProject(ctx, session, shared.RoleMember, project.ID.String()))
			require.NoError(t, rbac.GrantRoleInAsset(ctx, session, shared.RoleMember, asset.ID.String()))

			require.NoError(t, f.App.ExternalEntityProviderService.CollectGarbage(ctx))

			assert.True(t, projectExists(t, f, project))
			assert.True(t, assetExists(t, f, asset))
		})
	})
}
