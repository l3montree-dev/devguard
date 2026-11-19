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

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSemver(t *testing.T) {
	env, err := assetVersionCelEnv()
	require.NoError(t, err)

	cases := []struct {
		expr     string
		expected bool
	}{
		{`semver("v1.10.0") > semver("v1.9.0")`, true},
		{`semver("1.0.0") == semver("v1.0.0")`, true},
		{`semver("v1.0.0-rc1") < semver("v1.0.0")`, true},
		{`semver("v2.0.0") <= semver("v1.0.0")`, false},
		{`semver("v1.0.1").minor == 0`, true},
		{`semver("v1.2.3").major == 1 && semver("v1.2.3").patch == 3`, true},
		{`semver("v1.0.0-rc1").prerelease == "rc1"`, true},
		{`isSemver("v1.2.3")`, true},
		{`isSemver("main")`, false},
	}

	for _, c := range cases {
		t.Run(c.expr, func(t *testing.T) {
			prg, err := compile(env, c.expr)
			require.NoError(t, err)
			result, err := evalBool(prg, map[string]any{"ref": map[string]any{}, "otherRefs": []any{}})
			require.NoError(t, err)
			assert.Equal(t, c.expected, result)
		})
	}

	t.Run("semver of a non semver string is an error", func(t *testing.T) {
		prg, err := compile(env, `semver("main") > semver("v1.0.0")`)
		require.NoError(t, err)
		_, err = evalBool(prg, map[string]any{"ref": map[string]any{}, "otherRefs": []any{}})
		assert.Error(t, err)
	})

	t.Run("unknown semver field does not compile", func(t *testing.T) {
		_, err := compile(env, `semver("v1.0.0").foo == 0`)
		assert.Error(t, err)
	})
}

func TestAssetVersionsToDelete(t *testing.T) {
	stale := time.Now().AddDate(0, 0, -10)
	fresh := time.Now()

	assetVersions := []models.AssetVersion{
		{Name: "main", Type: models.AssetVersionBranch, DefaultBranch: true, LastUploadAt: &stale},
		{Name: "feature", Type: models.AssetVersionBranch, LastUploadAt: &stale},
		{Name: "fresh-feature", Type: models.AssetVersionBranch, LastUploadAt: &fresh},
		{Name: "v1.9.0", Type: models.AssetVersionTag, LastUploadAt: &stale},
		{Name: "v1.10.0", Type: models.AssetVersionTag, LastUploadAt: &stale},
	}

	names := func(versions []models.AssetVersion) []string {
		return utils.Map(versions, func(v models.AssetVersion) string { return v.Name })
	}

	t.Run("the default policy deletes branches without a scan in the last 7 days", func(t *testing.T) {
		toDelete, err := AssetVersionsToDelete(DefaultAssetVersionRetentionPolicy, assetVersions)
		require.NoError(t, err)
		assert.Equal(t, []string{"feature"}, names(toDelete))
	})

	t.Run("keeps only the latest semver", func(t *testing.T) {
		policy := `isSemver(ref.name) && otherRefs
			.filter(other, isSemver(other.name))
			.all(other, semver(ref.name) >= semver(other.name))`
		toDelete, err := AssetVersionsToDelete(policy, assetVersions)
		require.NoError(t, err)
		assert.Equal(t, []string{"main", "feature", "fresh-feature", "v1.9.0"}, names(toDelete))
	})

	t.Run("keeps an asset version the policy fails to evaluate for", func(t *testing.T) {
		toDelete, err := AssetVersionsToDelete(`semver(ref.name) >= semver("v1.10.0")`, assetVersions)
		require.NoError(t, err)
		assert.Equal(t, []string{"v1.9.0"}, names(toDelete))
	})

	t.Run("an invalid policy is an error", func(t *testing.T) {
		_, err := AssetVersionsToDelete(`ref.name ==`, assetVersions)
		assert.Error(t, err)
	})
}
