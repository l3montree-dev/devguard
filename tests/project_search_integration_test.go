// Copyright 2026 L3montree GmbH and the DevGuard Contributors.
// SPDX-License-Identifier: AGPL-3.0-or-later

package tests

import (
	"context"
	"testing"

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
