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

package hashmigrations

import (
	"testing"
	"time"

	"github.com/l3montree-dev/devguard/celrules"
	"github.com/l3montree-dev/devguard/dtos"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func migrateLegacyConfig(t *testing.T, content string) []celrules.CompiledPackageRule {
	migrated, isLegacy, err := convertLegacyDependencyProxyConfig(content)
	require.NoError(t, err)
	require.True(t, isLegacy)
	rules, err := celrules.ParsePackageRules(migrated)
	require.NoError(t, err)
	return rules
}

func TestConvertLegacyDependencyProxyConfig(t *testing.T) {
	t.Run("glob rules keep last-match-wins semantics", func(t *testing.T) {
		rules := migrateLegacyConfig(t, `{"rules":"# comment\npkg:npm/*\n\n!pkg:npm/express@*\n","minReleaseAge":0}`)
		require.Len(t, rules, 2)

		cases := []struct {
			purl    string
			blocked bool
		}{
			{"pkg:npm/lodash@4.17.21", true},
			{"pkg:npm/express@4.0.0", false},
			{"pkg:npm/express-evil@1.0.0", true},
			{"pkg:pypi/requests@2.0.0", false},
		}
		for _, c := range cases {
			blocked, _, err := celrules.EvaluatePackage(rules, celrules.Package{Purl: c.purl})
			require.NoError(t, err)
			assert.Equal(t, c.blocked, blocked, c.purl)
		}
	})

	t.Run("regex characters in patterns are matched literally", func(t *testing.T) {
		rules := migrateLegacyConfig(t, `{"rules":"pkg:pypi/a.b@1.0"}`)
		blocked, _, err := celrules.EvaluatePackage(rules, celrules.Package{Purl: "pkg:pypi/axb@1.0"})
		require.NoError(t, err)
		assert.False(t, blocked)
		blocked, _, err = celrules.EvaluatePackage(rules, celrules.Package{Purl: "pkg:pypi/a.b@1.0"})
		require.NoError(t, err)
		assert.True(t, blocked)
	})

	t.Run("min release age cannot be bypassed by allow rules", func(t *testing.T) {
		rules := migrateLegacyConfig(t, `{"rules":"!pkg:npm/express@*","minReleaseAge":24}`)

		blocked, _, err := celrules.EvaluatePackage(rules, celrules.Package{Purl: "pkg:npm/express@5.0.0", ReleasedAt: time.Now().Add(-time.Hour)})
		require.NoError(t, err)
		assert.True(t, blocked)

		blocked, _, err = celrules.EvaluatePackage(rules, celrules.Package{Purl: "pkg:npm/express@5.0.0", ReleasedAt: time.Now().Add(-48 * time.Hour)})
		require.NoError(t, err)
		assert.False(t, blocked)
	})

	t.Run("min release age ignores packages without release time", func(t *testing.T) {
		rules := migrateLegacyConfig(t, `{"rules":"","minReleaseAge":24}`)
		blocked, _, err := celrules.EvaluatePackage(rules, celrules.Package{Purl: "pkg:oci/nginx"})
		require.NoError(t, err)
		assert.False(t, blocked)
	})

	t.Run("registries", func(t *testing.T) {
		migrated, isLegacy, err := convertLegacyDependencyProxyConfig(`{"rules":"","registries":{"npm":"https://npm.example.com","deb":"https://deb.example.com"}}`)
		require.NoError(t, err)
		require.True(t, isLegacy)

		var cfg dtos.DependencyProxyConfig
		require.NoError(t, yaml.Unmarshal([]byte(migrated), &cfg))
		assert.Equal(t, "https://npm.example.com", cfg.Registries["npm"].GetURL())
		require.NotNil(t, cfg.Registries.DebConfig())
		assert.Equal(t, "https://deb.example.com", cfg.Registries.DebConfig().GetURL())
		assert.Nil(t, cfg.Registries.DebConfig().Keyring)
	})

	t.Run("new configs are not touched", func(t *testing.T) {
		for _, content := range []string{
			"rules:\n  - name: x\n    action: deny\n    expr: pkg.name == \"x\"\n",
			`{"registries":{"npm":"https://npm.example.com"}}`,
			"",
		} {
			_, isLegacy, err := convertLegacyDependencyProxyConfig(content)
			require.NoError(t, err)
			assert.False(t, isLegacy, content)
		}
	})
}
