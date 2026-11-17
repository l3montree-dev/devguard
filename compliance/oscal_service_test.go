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

package compliance

import (
	"os"
	"strings"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func readTestCatalog(t *testing.T) []byte {
	data, err := os.ReadFile("testfiles/oscal/catalog.json")
	require.NoError(t, err)
	return data
}

func controlsByID(controls []models.FrameworkControl) map[string]models.FrameworkControl {
	m := make(map[string]models.FrameworkControl, len(controls))
	for _, c := range controls {
		m[c.ControlID] = c
	}
	return m
}

func TestParseCatalog(t *testing.T) {
	name, controls, err := ParseCatalog(readTestCatalog(t))
	require.NoError(t, err)

	assert.Equal(t, "Test Catalog", name)
	require.Len(t, controls, 3)

	byID := controlsByID(controls)
	assert.Equal(t, "Review access monthly.", byID["C.1"].Description, "params should be resolved")
	require.NotNil(t, byID["C.1.1"].ParentControlID)
	assert.Equal(t, "C.1", *byID["C.1.1"].ParentControlID)
	assert.Nil(t, byID["C.1"].ParentControlID)

	for _, c := range controls {
		assert.Len(t, c.ControlHash, 64)
		assert.Equal(t, c.CalculateHash(), c.ControlHash)
	}
}

func TestParseCatalog_InvalidDocument(t *testing.T) {
	_, _, err := ParseCatalog([]byte(`{"component-definition": {}}`))
	assert.Error(t, err)
}

func TestCalculateControlHash(t *testing.T) {
	t.Run("parsing the same catalog twice yields the same hashes", func(t *testing.T) {
		_, first, err := ParseCatalog(readTestCatalog(t))
		require.NoError(t, err)
		_, second, err := ParseCatalog(readTestCatalog(t))
		require.NoError(t, err)

		for i := range first {
			assert.Equal(t, first[i].ControlHash, second[i].ControlHash)
		}
	})

	t.Run("the same control in another catalog yields the same hash", func(t *testing.T) {
		other := strings.Replace(string(readTestCatalog(t)), `"title": "Test Catalog"`, `"title": "Other Catalog"`, 1)

		_, first, err := ParseCatalog(readTestCatalog(t))
		require.NoError(t, err)
		_, second, err := ParseCatalog([]byte(other))
		require.NoError(t, err)

		assert.Equal(t, controlsByID(first)["C.2"].ControlHash, controlsByID(second)["C.2"].ControlHash)
	})

	t.Run("a different param value yields a different hash", func(t *testing.T) {
		changed := strings.Replace(string(readTestCatalog(t)), `"values": ["monthly"]`, `"values": ["weekly"]`, 1)

		_, first, err := ParseCatalog(readTestCatalog(t))
		require.NoError(t, err)
		_, second, err := ParseCatalog([]byte(changed))
		require.NoError(t, err)

		assert.NotEqual(t, controlsByID(first)["C.1"].ControlHash, controlsByID(second)["C.1"].ControlHash)
		assert.Equal(t, controlsByID(first)["C.2"].ControlHash, controlsByID(second)["C.2"].ControlHash)
	})

	t.Run("the parent control is part of the hash", func(t *testing.T) {
		parent := "C.1"
		otherParent := "C.9"
		c := models.FrameworkControl{ControlID: "C.1.1", Title: "Sub Control", ParentControlID: &parent}
		withOtherParent := c
		withOtherParent.ParentControlID = &otherParent

		assert.NotEqual(t, c.CalculateHash(), withOtherParent.CalculateHash())
	})
}

func TestParseComponentDefinition(t *testing.T) {
	data, err := os.ReadFile("testfiles/oscal/component-definition.json")
	require.NoError(t, err)

	name, components, err := ParseComponentDefinition(data)
	require.NoError(t, err)

	assert.Equal(t, "Test Components", name)
	require.Len(t, components, 1)
	assert.Equal(t, "8f7e6d5c-4b3a-4291-8f7e-6d5c4b3a2910", components[0].UUID.String())
	assert.Equal(t, "Branch Protection", components[0].Title)
	require.Len(t, components[0].ImplementedControls, 1)
	assert.Equal(t, "Test Catalog:C.1", components[0].ImplementedControls[0].FrameworkControlID)
	assert.Equal(t, "Enforce reviews", components[0].ImplementedControls[0].Description)
}
