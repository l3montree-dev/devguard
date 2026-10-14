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
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestFilterGoVersionList(t *testing.T) {
	now := time.Now()
	times := map[string]time.Time{
		"v0.9.0":  now.Add(-200 * time.Hour),
		"v1.0.0":  now.Add(-100 * time.Hour),
		"v1.1.0":  now.Add(-1 * time.Hour),
		"v1.9.0":  now.Add(-100 * time.Hour),
		"v1.10.0": now.Add(-1 * time.Hour),
	}
	var lookedUp []string
	releaseTime := func(v string) (time.Time, error) {
		lookedUp = append(lookedUp, v)
		if t, ok := times[v]; ok {
			return t, nil
		}
		return time.Time{}, errors.New("unknown")
	}
	allowAll := func(string) bool { return true }
	list := []byte("v0.9.0\nv1.0.0\nv1.1.0\n")

	t.Run("without minimum age only rules filter", func(t *testing.T) {
		lookedUp = nil
		out, removed := filterGoVersionList(list, 0, releaseTime, func(v string) bool { return v != "v1.0.0" })
		assert.Equal(t, "v0.9.0\nv1.1.0\n", string(out))
		assert.Equal(t, 1, removed)
		assert.Empty(t, lookedUp, "no release times needed without a minimum age")
	})

	t.Run("removes too new versions above the first old enough one", func(t *testing.T) {
		lookedUp = nil
		out, removed := filterGoVersionList(list, 24*time.Hour, releaseTime, allowAll)
		assert.Equal(t, "v0.9.0\nv1.0.0\n", string(out))
		assert.Equal(t, 1, removed)
		// stops at v1.0.0 - v0.9.0 is kept without a lookup
		assert.Equal(t, []string{"v1.1.0", "v1.0.0"}, lookedUp)
	})

	t.Run("versions with unknown release time are removed", func(t *testing.T) {
		out, _ := filterGoVersionList([]byte("v1.0.0\nv3.0.0\n"), 24*time.Hour, releaseTime, allowAll)
		assert.Equal(t, "v1.0.0\n", string(out))
	})

	t.Run("compares semver, not strings", func(t *testing.T) {
		out, _ := filterGoVersionList([]byte("v1.9.0\nv1.10.0\n"), 24*time.Hour, releaseTime, allowAll)
		assert.Equal(t, "v1.9.0\n", string(out))
	})

	t.Run("rules are applied before the minimum age", func(t *testing.T) {
		lookedUp = nil
		out, _ := filterGoVersionList(list, 24*time.Hour, releaseTime, func(v string) bool { return v != "v1.1.0" })
		assert.Equal(t, "v0.9.0\nv1.0.0\n", string(out))
		assert.Equal(t, []string{"v1.0.0"}, lookedUp, "rule-blocked versions are not looked up")
	})

	t.Run("empty when nothing is allowed", func(t *testing.T) {
		out, removed := filterGoVersionList(list, 24*time.Hour, releaseTime, func(string) bool { return false })
		assert.Empty(t, out)
		assert.Equal(t, 3, removed)
	})
}
