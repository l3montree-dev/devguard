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

package dependencyfirewall

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterGoVersionList(t *testing.T) {
	list := []byte("v0.9.0\nv1.0.0\nv1.1.0\n")

	var checked []string
	allowedExcept := func(blocked ...string) func(string) bool {
		return func(v string) bool {
			checked = append(checked, v)
			for _, b := range blocked {
				if v == b {
					return false
				}
			}
			return true
		}
	}

	t.Run("keeps everything when the highest version is allowed", func(t *testing.T) {
		checked = nil
		out, removed := filterGoVersionList(list, allowedExcept())
		assert.Equal(t, string(list), string(out))
		assert.Equal(t, 0, removed)
		assert.Equal(t, []string{"v1.1.0"}, checked)
	})

	t.Run("removes blocked versions above the first allowed one", func(t *testing.T) {
		checked = nil
		out, removed := filterGoVersionList(list, allowedExcept("v1.1.0"))
		assert.Equal(t, "v0.9.0\nv1.0.0\n", string(out))
		assert.Equal(t, 1, removed)
		assert.Equal(t, []string{"v1.1.0", "v1.0.0"}, checked, "stops at the first allowed version")
	})

	t.Run("keeps lower versions without checking them", func(t *testing.T) {
		checked = nil
		out, _ := filterGoVersionList(list, allowedExcept("v1.1.0", "v0.9.0"))
		assert.Equal(t, "v0.9.0\nv1.0.0\n", string(out))
		assert.NotContains(t, checked, "v0.9.0")
	})

	t.Run("compares semver, not strings", func(t *testing.T) {
		out, _ := filterGoVersionList([]byte("v1.9.0\nv1.10.0\n"), allowedExcept("v1.10.0"))
		assert.Equal(t, "v1.9.0\n", string(out))
	})

	t.Run("empty when nothing is allowed", func(t *testing.T) {
		out, removed := filterGoVersionList(list, func(string) bool { return false })
		assert.Empty(t, out)
		assert.Equal(t, 3, removed)
	})
}
