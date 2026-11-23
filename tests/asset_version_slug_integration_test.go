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

package tests

import (
	"context"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/database/repositories"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAssetVersionSlugsAreUniquePerAsset(t *testing.T) {
	db, _, terminate := InitDatabaseContainer("../initdb.sql")
	defer terminate()

	_, _, asset, _ := CreateOrgProjectAndAssetAssetVersion(db)
	repo := repositories.NewAssetVersionRepository(db)
	ctx := context.Background()

	t.Run("names sharing a slug get the next free one", func(t *testing.T) {
		branch, err := repo.FindOrCreate(ctx, nil, "feature/foo", asset.ID, false, nil)
		require.NoError(t, err)
		assert.Equal(t, "feature-foo", branch.Slug)

		sameSlug, err := repo.FindOrCreate(ctx, nil, "feature-foo", asset.ID, false, nil)
		require.NoError(t, err)
		assert.Equal(t, "feature-foo-1", sameSlug.Slug)

		again, err := repo.FindOrCreate(ctx, nil, "feature/foo", asset.ID, false, nil)
		require.NoError(t, err)
		assert.Equal(t, branch.ID, again.ID)
	})

	t.Run("a release tag is found by its name", func(t *testing.T) {
		tag, err := repo.FindOrCreate(ctx, nil, "v1.19.1", asset.ID, true, nil)
		require.NoError(t, err)
		assert.Equal(t, "v1-19-1", tag.Slug)

		byName, err := repo.ReadByName(ctx, nil, "v1.19.1", asset.ID)
		require.NoError(t, err)
		assert.Equal(t, tag.ID, byName.ID)
	})

	t.Run("the database rejects a duplicate slug", func(t *testing.T) {
		err := db.Create(&models.AssetVersion{Name: "feature_foo", AssetID: asset.ID, Slug: "feature-foo", Type: "branch"}).Error
		assert.ErrorContains(t, err, "asset_versions_asset_id_slug_unique")
	})
}
