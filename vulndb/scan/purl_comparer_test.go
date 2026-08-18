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
	"context"
	"sync"
	"testing"

	"github.com/l3montree-dev/devguard/database/models"
	"github.com/l3montree-dev/devguard/normalize"
	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustParsePurl(t *testing.T, purl string) packageurl.PackageURL {
	t.Helper()
	parsed, err := packageurl.FromString(purl)
	require.NoError(t, err)
	return parsed
}

func candidateFor(t *testing.T, purl string, components ...models.AffectedComponent) *candidate {
	t.Helper()
	c := newCandidate(mustParsePurl(t, purl))
	c.Components = components
	return c
}

// warmCache stores candidates under the generation that is current right now,
// which is what a resolve without a concurrent flush does
func warmCache(acc *AffectedComponentsCache, candidates ...*candidate) {
	acc.SetForCandidates(candidates, acc.GetCurrentGeneration())
}

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

func TestCandidateCacheKey(t *testing.T) {
	t.Run("purls resolving to the same package and version share a key", func(t *testing.T) {
		// the qualifiers are stripped from the search purl, so both end up in the same bucket
		a := candidateFor(t, "pkg:npm/lodash@4.17.20")
		b := candidateFor(t, "pkg:npm/lodash@4.17.20?arch=amd64")
		assert.Equal(t, a.cacheKey(), b.cacheKey())
	})

	t.Run("different versions of the same package differ", func(t *testing.T) {
		a := candidateFor(t, "pkg:npm/lodash@4.17.20")
		b := candidateFor(t, "pkg:npm/lodash@4.17.21")
		assert.NotEqual(t, a.cacheKey(), b.cacheKey())
	})

	t.Run("same package and version but different distro differ", func(t *testing.T) {
		// same lookup key, but the ecosystem pattern narrows the query differently
		a := candidateFor(t, "pkg:deb/debian/git@2.47.3?distro=debian-13.2")
		b := candidateFor(t, "pkg:deb/debian/git@2.47.3?distro=debian-12.5")
		require.Equal(t, a.lookupKey(), b.lookupKey())
		assert.NotEqual(t, a.cacheKey(), b.cacheKey())
	})

	t.Run("same package and version but different version interpretation differ", func(t *testing.T) {
		a := candidateFor(t, "pkg:npm/lodash@4.17.20")
		b := candidateFor(t, "pkg:npm/lodash@4.17.20")
		b.shape.interpretation = normalize.ExactVersionString
		require.Equal(t, normalize.SemanticVersionString, a.shape.interpretation)
		assert.NotEqual(t, a.cacheKey(), b.cacheKey())
	})
}

func TestAffectedComponentsCache(t *testing.T) {
	var cacheSize = 50
	t.Run("lookup on an untouched cache is a miss", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		components, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.False(t, ok)
		assert.Nil(t, components)
	})

	t.Run("stored components are returned again", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		stored := candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1})
		warmCache(acc, stored)

		components, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.True(t, ok)
		assert.Equal(t, stored.Components, components)
	})

	t.Run("an empty result is cached as a hit", func(t *testing.T) {
		// negative caching - a package without affected components must not be queried again
		acc := NewAffectedComponentsCache(&cacheSize)
		warmCache(acc, candidateFor(t, "pkg:npm/lodash@4.17.20"))

		components, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.True(t, ok)
		assert.Empty(t, components)
	})

	t.Run("entries of one purl do not leak into another distro", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		warmCache(acc, candidateFor(t, "pkg:deb/debian/git@2.47.3?distro=debian-13.2", models.AffectedComponent{ID: 1, Ecosystem: "Debian:13"}))

		components, ok := acc.GetByCandidate(candidateFor(t, "pkg:deb/debian/git@2.47.3?distro=debian-12.5"))
		assert.False(t, ok)
		assert.Nil(t, components)
	})

	t.Run("flush drops every entry", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		warmCache(acc,
			candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1}),
			candidateFor(t, "pkg:npm/express@4.18.2", models.AffectedComponent{ID: 2}),
		)
		acc.Flush()

		_, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.False(t, ok)
		_, ok = acc.GetByCandidate(candidateFor(t, "pkg:npm/express@4.18.2"))
		assert.False(t, ok)
	})

	t.Run("writing after a flush works again", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		acc.Flush()
		warmCache(acc, candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1}))

		components, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.True(t, ok)
		assert.Len(t, components, 1)
	})

	t.Run("values collected before a flush are not written back", func(t *testing.T) {
		// an import flushing mid scan must not let the scan restore its now
		// outdated components into the fresh generation
		acc := NewAffectedComponentsCache(&cacheSize)
		outdated := candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1})

		generation := acc.GetCurrentGeneration()
		acc.Flush()
		acc.SetForCandidates([]*candidate{outdated}, generation)

		_, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.False(t, ok)
	})

	t.Run("a flush does not block writes started after it", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		acc.Flush()
		warmCache(acc, candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1}))

		components, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.True(t, ok)
		assert.Len(t, components, 1)
	})

	t.Run("only the outdated write is dropped", func(t *testing.T) {
		acc := NewAffectedComponentsCache(&cacheSize)
		outdatedGeneration := acc.GetCurrentGeneration()
		acc.Flush()

		acc.SetForCandidates([]*candidate{candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1})}, outdatedGeneration)
		warmCache(acc, candidateFor(t, "pkg:npm/express@4.18.2", models.AffectedComponent{ID: 2}))

		_, ok := acc.GetByCandidate(candidateFor(t, "pkg:npm/lodash@4.17.20"))
		assert.False(t, ok)
		_, ok = acc.GetByCandidate(candidateFor(t, "pkg:npm/express@4.18.2"))
		assert.True(t, ok)
	})

	t.Run("concurrent reads writes and flushes are safe", func(t *testing.T) {
		// only meaningful under -race, which the pipeline runs
		acc := NewAffectedComponentsCache(&cacheSize)
		purls := []string{"pkg:npm/lodash@4.17.20", "pkg:npm/express@4.18.2", "pkg:deb/debian/git@2.47.3?distro=debian-13.2"}

		var wg sync.WaitGroup
		for i := range purls {
			wg.Add(3)
			go func() {
				defer wg.Done()
				warmCache(acc, candidateFor(t, purls[i], models.AffectedComponent{ID: int64(i)}))
			}()
			go func() {
				defer wg.Done()
				acc.GetByCandidate(candidateFor(t, purls[i]))
			}()
			go func() {
				defer wg.Done()
				acc.Flush()
			}()
		}
		wg.Wait()
	})
}

func TestResolveCandidatesUsesCache(t *testing.T) {
	// the comparer has no database - every lookup that is not served by the
	// cache panics, which is exactly what these tests assert against
	comparer := NewPurlComparer(nil, new(50))

	t.Run("cached purls are resolved without touching the database", func(t *testing.T) {

		purl := mustParsePurl(t, "pkg:npm/lodash@4.17.20")
		warmCache(comparer.cache, candidateFor(t, "pkg:npm/lodash@4.17.20", models.AffectedComponent{ID: 1}))

		components, err := comparer.GetAffectedComponents(context.Background(), purl)
		require.NoError(t, err)
		assert.Len(t, components, 1)
		assert.Equal(t, int64(1), components[0].ID)
	})
}
