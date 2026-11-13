// Copyright 2026 L3montree GmbH and the DevGuard Contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectSearchPreservesAvatars(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("search-avatars")
		root := f.CreateProject(org.ID, "root")
		child := f.CreateProject(org.ID, "child")
		require.NoError(t, f.DB.Model(&child).Update("parent_id", root.ID).Error)
		asset := f.CreateAsset(child.ID, "repository")
		withoutAvatar := f.CreateProject(org.ID, "without-avatar")

		rootAvatar, childAvatar, assetAvatar := "cm9vdA==", "Y2hpbGQ=", "YXNzZXQ="
		require.NoError(t, f.DB.Model(&root).Update("avatar", rootAvatar).Error)
		require.NoError(t, f.DB.Model(&child).Update("avatar", childAvatar).Error)
		require.NoError(t, f.DB.Model(&asset).Update("avatar", assetAvatar).Error)

		for _, tc := range []struct {
			name   string
			search string
			depth  int
		}{
			{name: "matching root", search: root.Name, depth: 0},
			{name: "matching subgroup and its parent", search: child.Name, depth: 1},
			{name: "matching asset and its ancestor chain", search: asset.Name, depth: 2},
		} {
			t.Run(tc.name, func(t *testing.T) {
				result, err := f.App.ProjectRepository.SearchProjectsWithSubProjectsAndAssetsPaged(
					context.Background(), nil, []string{asset.ID.String()},
					[]string{root.ID.String(), child.ID.String()}, nil, org.ID,
					shared.PageInfo{Page: 1, PageSize: 10}, tc.search, nil, nil,
				)
				require.NoError(t, err)
				assert.EqualValues(t, 1, result.Total)
				require.Len(t, result.Data, 1)
				assert.Equal(t, root.ID, result.Data[0].ID)
				assert.Equal(t, &rootAvatar, result.Data[0].Avatar)
				if tc.depth >= 1 {
					require.Len(t, result.Data[0].SubGroupsAndAssets, 1)
					subgroup := result.Data[0].SubGroupsAndAssets[0]
					assert.Equal(t, child.ID, subgroup.ID)
					assert.Equal(t, &childAvatar, subgroup.Avatar)
					if tc.depth == 2 {
						require.Len(t, subgroup.SubGroupsAndAssets, 1)
						assert.Equal(t, asset.ID, subgroup.SubGroupsAndAssets[0].ID)
						assert.Equal(t, &assetAvatar, subgroup.SubGroupsAndAssets[0].Avatar)
					}
				}
			})
		}

		t.Run("project without an avatar", func(t *testing.T) {
			result, err := f.App.ProjectRepository.SearchProjectsWithSubProjectsAndAssetsPaged(
				context.Background(), nil, nil, []string{withoutAvatar.ID.String()}, nil, org.ID,
				shared.PageInfo{Page: 1, PageSize: 10}, withoutAvatar.Name, nil, nil,
			)
			require.NoError(t, err)
			require.Len(t, result.Data, 1)
			assert.Equal(t, withoutAvatar.ID, result.Data[0].ID)
			assert.Nil(t, result.Data[0].Avatar)
		})
	})
}

func TestProjectSearchRespectsSubgroup(t *testing.T) {
	t.Parallel()
	WithTestApp(t, "../initdb.sql", func(f *TestFixture) {
		org := f.CreateOrg("search-subgroup")

		// Tree: root -> subgroup -> {matching asset, matching nested subgroup}.
		root := f.CreateProject(org.ID, "root")
		subgroup := f.CreateProject(org.ID, "subgroup")
		require.NoError(t, f.DB.Model(&subgroup).Update("parent_id", root.ID).Error)

		insideAsset := f.CreateAsset(subgroup.ID, "needle-inside-asset")
		nested := f.CreateProject(org.ID, "needle-nested-group")
		require.NoError(t, f.DB.Model(&nested).Update("parent_id", subgroup.ID).Error)

		outsideProject := f.CreateProject(org.ID, "needle-outside-group")
		require.NoError(t, f.DB.Model(&outsideProject).Update("parent_id", root.ID).Error)
		outsideAsset := f.CreateAsset(root.ID, "needle-outside-asset")

		allowedAssets := []string{insideAsset.ID.String(), outsideAsset.ID.String()}
		allowedProjects := []string{
			root.ID.String(), subgroup.ID.String(), nested.ID.String(), outsideProject.ID.String(),
		}

		t.Run("without a parent the whole organization is searched", func(t *testing.T) {
			result, err := f.App.ProjectRepository.SearchProjectsWithSubProjectsAndAssetsPaged(
				context.Background(), nil, allowedAssets, allowedProjects, nil, org.ID,
				shared.PageInfo{Page: 1, PageSize: 50}, "needle", nil, nil,
			)
			require.NoError(t, err)
			// insideAsset, nested, outsideProject and outsideAsset all match.
			assert.EqualValues(t, 4, result.Total)
		})

		t.Run("inside a subgroup only its elements are returned", func(t *testing.T) {
			result, err := f.App.ProjectRepository.SearchProjectsWithSubProjectsAndAssetsPaged(
				context.Background(), nil, allowedAssets, allowedProjects, &subgroup.ID, org.ID,
				shared.PageInfo{Page: 1, PageSize: 50}, "needle", nil, nil,
			)
			require.NoError(t, err)
			// Only insideAsset and nested live under the subgroup.
			assert.EqualValues(t, 2, result.Total)

			require.Len(t, result.Data, 1)
			assert.Equal(t, subgroup.ID, result.Data[0].ID)

			gotIDs := map[uuid.UUID]bool{}
			for _, child := range result.Data[0].SubGroupsAndAssets {
				gotIDs[child.ID] = true
			}
			assert.True(t, gotIDs[insideAsset.ID], "the subgroup asset should be returned")
			assert.True(t, gotIDs[nested.ID], "the nested subgroup should be returned")
			assert.False(t, gotIDs[outsideProject.ID], "a sibling project must not leak in")
			assert.False(t, gotIDs[outsideAsset.ID], "a sibling asset must not leak in")
		})
	})
}
