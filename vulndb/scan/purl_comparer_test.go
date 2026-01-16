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

package scan

import (
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/stretchr/testify/assert"
)

func TestDeduplicateByAlias(t *testing.T) {
	t.Run("empty input returns empty", func(t *testing.T) {
		result := deduplicateByAlias([]models.VulnInPackage{})
		assert.Empty(t, result)
	})

	t.Run("single vuln returns unchanged", func(t *testing.T) {
		vulns := []models.VulnInPackage{
			{CVEID: "CVE-2024-1234", CVE: models.CVE{CVE: "CVE-2024-1234"}},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 1)
		assert.Equal(t, "CVE-2024-1234", result[0].CVEID)
	})

	t.Run("no aliases returns all vulns", func(t *testing.T) {
		vulns := []models.VulnInPackage{
			{CVEID: "CVE-2024-1111", CVE: models.CVE{CVE: "CVE-2024-1111"}},
			{CVEID: "CVE-2024-2222", CVE: models.CVE{CVE: "CVE-2024-2222"}},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 2)
	})

	t.Run("unidirectional alias removes target", func(t *testing.T) {
		// CVE-2024-1111 --alias--> CVE-2024-2222
		// Should keep CVE-2024-1111, remove CVE-2024-2222
		vulns := []models.VulnInPackage{
			{
				CVEID: "CVE-2024-1111",
				CVE: models.CVE{
					CVE: "CVE-2024-1111",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-1111", TargetCVE: "CVE-2024-2222", RelationshipType: "alias"},
					},
				},
			},
			{
				CVEID: "CVE-2024-2222",
				CVE:   models.CVE{CVE: "CVE-2024-2222"},
			},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 1)
		assert.Equal(t, "CVE-2024-1111", result[0].CVEID)
	})

	t.Run("bidirectional alias keeps lexicographically smaller", func(t *testing.T) {
		// CVE-2024-1111 <--alias--> CVE-2024-2222
		// Should keep CVE-2024-1111 (smaller)
		vulns := []models.VulnInPackage{
			{
				CVEID: "CVE-2024-1111",
				CVE: models.CVE{
					CVE: "CVE-2024-1111",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-1111", TargetCVE: "CVE-2024-2222", RelationshipType: "alias"},
					},
				},
			},
			{
				CVEID: "CVE-2024-2222",
				CVE: models.CVE{
					CVE: "CVE-2024-2222",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-2222", TargetCVE: "CVE-2024-1111", RelationshipType: "alias"},
					},
				},
			},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 1)
		assert.Equal(t, "CVE-2024-1111", result[0].CVEID)
	})

	t.Run("bidirectional alias keeps smaller even when order reversed", func(t *testing.T) {
		// Same as above but vulns in different order
		vulns := []models.VulnInPackage{
			{
				CVEID: "CVE-2024-2222",
				CVE: models.CVE{
					CVE: "CVE-2024-2222",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-2222", TargetCVE: "CVE-2024-1111", RelationshipType: "alias"},
					},
				},
			},
			{
				CVEID: "CVE-2024-1111",
				CVE: models.CVE{
					CVE: "CVE-2024-1111",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-1111", TargetCVE: "CVE-2024-2222", RelationshipType: "alias"},
					},
				},
			},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 1)
		assert.Equal(t, "CVE-2024-1111", result[0].CVEID)
	})

	t.Run("related relationship does not deduplicate", func(t *testing.T) {
		// CVE-2024-1111 --related--> CVE-2024-2222 (not alias)
		// Should keep both
		vulns := []models.VulnInPackage{
			{
				CVEID: "CVE-2024-1111",
				CVE: models.CVE{
					CVE: "CVE-2024-1111",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-1111", TargetCVE: "CVE-2024-2222", RelationshipType: "related"},
					},
				},
			},
			{
				CVEID: "CVE-2024-2222",
				CVE:   models.CVE{CVE: "CVE-2024-2222"},
			},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 2)
	})

	t.Run("chain of aliases", func(t *testing.T) {
		// CVE-2024-1111 --alias--> CVE-2024-2222 --alias--> CVE-2024-3333
		// Should keep CVE-2024-1111, remove both 2222 and 3333
		vulns := []models.VulnInPackage{
			{
				CVEID: "CVE-2024-1111",
				CVE: models.CVE{
					CVE: "CVE-2024-1111",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-1111", TargetCVE: "CVE-2024-2222", RelationshipType: "alias"},
					},
				},
			},
			{
				CVEID: "CVE-2024-2222",
				CVE: models.CVE{
					CVE: "CVE-2024-2222",
					Relationships: []models.CVERelationship{
						{SourceCVE: "CVE-2024-2222", TargetCVE: "CVE-2024-3333", RelationshipType: "alias"},
					},
				},
			},
			{
				CVEID: "CVE-2024-3333",
				CVE:   models.CVE{CVE: "CVE-2024-3333"},
			},
		}
		result := deduplicateByAlias(vulns)
		assert.Len(t, result, 1) // 1111

		// Verify 3333 is removed (it's a target of 2222)
		cveIDs := make(map[string]bool)
		for _, v := range result {
			cveIDs[v.CVEID] = true
		}
		assert.True(t, cveIDs["CVE-2024-1111"])
		assert.False(t, cveIDs["CVE-2024-3333"])
		assert.False(t, cveIDs["CVE-2024-2222"])
	})
}
