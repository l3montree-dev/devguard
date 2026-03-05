// Copyright (C) 2025 l3montree GmbH
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

package shared_test

import (
	"testing"

	"github.com/l3montree-dev/devguard/shared"
	"github.com/stretchr/testify/assert"
)

func TestIdentityName(t *testing.T) {
	t.Run("v1 schema: name is a plain string", func(t *testing.T) {
		traits := map[string]any{"name": "Alice"}
		assert.Equal(t, "Alice", shared.IdentityName(traits))
	})

	t.Run("pre-v1 schema: name is a map with first and last", func(t *testing.T) {
		traits := map[string]any{
			"name": map[string]any{"first": "Alice", "last": "Smith"},
		}
		assert.Equal(t, "Alice Smith", shared.IdentityName(traits))
	})

	t.Run("pre-v1 schema: only first name present", func(t *testing.T) {
		traits := map[string]any{
			"name": map[string]any{"first": "Alice"},
		}
		assert.Equal(t, "Alice", shared.IdentityName(traits))
	})

	t.Run("pre-v1 schema: only last name present", func(t *testing.T) {
		traits := map[string]any{
			"name": map[string]any{"last": "Smith"},
		}
		assert.Equal(t, "Smith", shared.IdentityName(traits))
	})

	t.Run("name key missing", func(t *testing.T) {
		traits := map[string]any{"email": "alice@example.com"}
		assert.Equal(t, "", shared.IdentityName(traits))
	})

	t.Run("name key is nil", func(t *testing.T) {
		traits := map[string]any{"name": nil}
		assert.Equal(t, "", shared.IdentityName(traits))
	})

	t.Run("traits is nil", func(t *testing.T) {
		assert.Equal(t, "", shared.IdentityName(nil))
	})

	t.Run("traits is not a map", func(t *testing.T) {
		assert.Equal(t, "", shared.IdentityName("not a map"))
	})

	t.Run("name is an unexpected type", func(t *testing.T) {
		traits := map[string]any{"name": 42}
		assert.Equal(t, "", shared.IdentityName(traits))
	})
}

func TestIdentityEmail(t *testing.T) {
	t.Run("email present", func(t *testing.T) {
		traits := map[string]any{"email": "alice@example.com"}
		assert.Equal(t, "alice@example.com", shared.IdentityEmail(traits))
	})

	t.Run("email key missing", func(t *testing.T) {
		traits := map[string]any{"name": "Alice"}
		assert.Equal(t, "", shared.IdentityEmail(traits))
	})

	t.Run("email is nil", func(t *testing.T) {
		traits := map[string]any{"email": nil}
		assert.Equal(t, "", shared.IdentityEmail(traits))
	})

	t.Run("email is not a string", func(t *testing.T) {
		traits := map[string]any{"email": 123}
		assert.Equal(t, "", shared.IdentityEmail(traits))
	})

	t.Run("traits is nil", func(t *testing.T) {
		assert.Equal(t, "", shared.IdentityEmail(nil))
	})

	t.Run("traits is not a map", func(t *testing.T) {
		assert.Equal(t, "", shared.IdentityEmail("not a map"))
	})
}
