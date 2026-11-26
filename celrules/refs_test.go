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

	main := models.AssetVersion{ID: uuid.New(), Name: "main", Type: models.AssetVersionBranch, DefaultBranch: true}
	v1_9 := models.AssetVersion{ID: uuid.New(), Name: "v1.9.0", Type: models.AssetVersionTag}
	v1_12 := models.AssetVersion{ID: uuid.New(), Name: "1.12.1", Type: models.AssetVersionTag}
	rc := models.AssetVersion{ID: uuid.New(), Name: "v2.0.0-rc1", Type: models.AssetVersionTag}
	cryptic := models.AssetVersion{ID: uuid.New(), Name: "release-final", Type: models.AssetVersionTag}
	semverBranch := models.AssetVersion{ID: uuid.New(), Name: "3.0.0", Type: models.AssetVersionBranch}
	refs := NewRefs([]models.AssetVersion{main, v1_9, v1_12, rc, cryptic, semverBranch})

	t.Run("the highest semver tag is the latest", func(t *testing.T) {
		assert.True(t, eval(t, `ref.isLatest`, refs, v1_12.ID))
		assert.False(t, eval(t, `ref.isLatest`, refs, v1_9.ID))
	})

	t.Run("prereleases, branches and non semver tags are never the latest", func(t *testing.T) {
		assert.False(t, eval(t, `ref.isLatest`, refs, rc.ID))
		assert.False(t, eval(t, `ref.isLatest`, refs, semverBranch.ID))
		assert.False(t, eval(t, `ref.isLatest`, refs, cryptic.ID))
	})

	t.Run("every ref knows the latest ref", func(t *testing.T) {
		assert.True(t, eval(t, `ref.latestRef.name == "1.12.1"`, refs, main.ID))
		assert.True(t, eval(t, `otherRefs.exists(o, o.isLatest && o.name == ref.latestRef.name)`, refs, main.ID))
	})

	t.Run("latestRef is absent without any semver tag", func(t *testing.T) {
		refs := NewRefs([]models.AssetVersion{main, cryptic})
		assert.False(t, eval(t, `has(ref.latestRef)`, refs, main.ID))
		assert.False(t, eval(t, `ref.isLatest`, refs, cryptic.ID))
	})

	t.Run("an unknown asset version is an error", func(t *testing.T) {
		_, err := refs.Activation(uuid.New())
		assert.Error(t, err)
	})
}
