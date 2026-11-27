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

package celrules

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefs(t *testing.T) {
	env, err := assetVersionCelEnv()
	require.NoError(t, err)

	eval := func(t *testing.T, expr string, refs Refs, id uuid.UUID) bool {
		prg, err := compile(env, expr)
		require.NoError(t, err)
		activation, err := refs.Activation(id)
		require.NoError(t, err)
		result, err := evalBool(prg, activation)
		require.NoError(t, err)
		return result
	}

	now := time.Now()
	main := models.AssetVersion{ID: uuid.New(), Name: "main", Type: models.AssetVersionBranch, DefaultBranch: true, CreatedAt: now}
	v1_9_0 := models.AssetVersion{ID: uuid.New(), Name: "v1.9.0", Type: models.AssetVersionTag, CreatedAt: now.Add(-4 * time.Hour)}
	v1_9_3 := models.AssetVersion{ID: uuid.New(), Name: "v1.9.3", Type: models.AssetVersionTag, CreatedAt: now.Add(-1 * time.Hour)}
	v1_12 := models.AssetVersion{ID: uuid.New(), Name: "1.12.1", Type: models.AssetVersionTag, CreatedAt: now.Add(-2 * time.Hour)}
	v0_9 := models.AssetVersion{ID: uuid.New(), Name: "0.9.1", Type: models.AssetVersionTag, CreatedAt: now.Add(-5 * time.Hour)}
	rc := models.AssetVersion{ID: uuid.New(), Name: "v2.0.0-rc1", Type: models.AssetVersionTag, CreatedAt: now.Add(-3 * time.Hour)}
	cryptic := models.AssetVersion{ID: uuid.New(), Name: "release-final", Type: models.AssetVersionTag, CreatedAt: now.Add(-6 * time.Hour)}
	semverBranch := models.AssetVersion{ID: uuid.New(), Name: "3.0.0", Type: models.AssetVersionBranch, CreatedAt: now}
	all := []models.AssetVersion{main, v1_9_0, v1_9_3, v1_12, v0_9, rc, cryptic, semverBranch}
	refs := NewRefs(all)

	latestBy := func(t *testing.T, field string) []string {
		var names []string
		for _, av := range all {
			if eval(t, "ref."+field, refs, av.ID) {
				names = append(names, av.Name)
			}
		}
		return names
	}

	t.Run("isLatestBySemverIncludingPrereleases includes prereleases", func(t *testing.T) {
		assert.Equal(t, []string{"v2.0.0-rc1"}, latestBy(t, "isLatestBySemverIncludingPrereleases"))
	})

	t.Run("isLatestBySemverStable ignores prereleases", func(t *testing.T) {
		assert.Equal(t, []string{"1.12.1"}, latestBy(t, "isLatestBySemverStable"))
	})

	t.Run("isLatestBySemverInMajor marks one stable tag per major", func(t *testing.T) {
		assert.Equal(t, []string{"1.12.1", "0.9.1"}, latestBy(t, "isLatestBySemverInMajor"))
	})

	t.Run("isLatestBySemverInMinor marks one stable tag per minor", func(t *testing.T) {
		assert.Equal(t, []string{"v1.9.3", "1.12.1", "0.9.1"}, latestBy(t, "isLatestBySemverInMinor"))
	})

	t.Run("isLatestByCreatedAt only considers tags", func(t *testing.T) {
		assert.Equal(t, []string{"v1.9.3"}, latestBy(t, "isLatestByCreatedAt"))
	})

	t.Run("other refs expose the latest fields", func(t *testing.T) {
		assert.True(t, eval(t, `otherRefs.exists(o, o.isLatestBySemverStable && o.name == "1.12.1")`, refs, main.ID))
	})

	t.Run("all fields are false without any tag", func(t *testing.T) {
		refs := NewRefs([]models.AssetVersion{main})
		assert.False(t, eval(t, `ref.isLatestBySemverIncludingPrereleases || ref.isLatestBySemverStable || ref.isLatestBySemverInMajor || ref.isLatestBySemverInMinor || ref.isLatestByCreatedAt`, refs, main.ID))
	})

	t.Run("an unknown asset version is an error", func(t *testing.T) {
		_, err := refs.Activation(uuid.New())
		assert.Error(t, err)
	})
}
